// Package telemetry holds vulnapi's Argvio product metrics that are not tied to
// one package: the outcome of the HTTP requests a scan sends, and the class of
// the errors that stop a request or a check. Metric names, dimensions and the
// values they take are declared in the Argvio catalog. Every dimension value
// comes from a fixed list in this package, never from the target, the scanned
// spec or an error message.
package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/getargvio/argvio-go"
)

// Error classes, the values of the reason dimension.
const (
	ReasonCanceled = "canceled"
	ReasonTimeout  = "timeout"
	ReasonDNS      = "dns"
	ReasonRefused  = "refused"
	ReasonReset    = "reset"
	ReasonTLS      = "tls"
	ReasonOther    = "other"
)

var (
	requests        = argvio.NewCounter("http.requests", argvio.Dims("status"))
	requestErrors   = argvio.NewCounter("http.errors", argvio.Dims("reason"))
	requestDuration = argvio.NewDuration("http.request-duration")
)

// ErrorClass sorts err into one of the Reason* classes. It only looks at the
// error's type, so nothing from its message (a host, a URL, a path) leaves the
// machine.
func ErrorClass(err error) string {
	var (
		dnsErr      *net.DNSError
		unknownCA   x509.UnknownAuthorityError
		hostnameErr x509.HostnameError
		invalidCert x509.CertificateInvalidError
		verifyErr   *tls.CertificateVerificationError
		recordErr   tls.RecordHeaderError
		netErr      net.Error
	)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.Canceled):
		return ReasonCanceled
	case errors.As(err, &dnsErr):
		return ReasonDNS
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()):
		return ReasonTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ReasonRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return ReasonReset
	case errors.As(err, &unknownCA), errors.As(err, &hostnameErr), errors.As(err, &invalidCert),
		errors.As(err, &verifyErr), errors.As(err, &recordErr):
		return ReasonTLS
	default:
		return ReasonOther
	}
}

// StatusLabel is the status dimension of http.requests: the codes a scan
// cares about on their own (authentication and rate limiting), the other codes
// by class, and "error" when no response came back.
func StatusLabel(resp *http.Response, err error) string {
	if err != nil || resp == nil {
		return "error"
	}
	switch code := resp.StatusCode; {
	case code == http.StatusUnauthorized:
		return "401"
	case code == http.StatusForbidden:
		return "403"
	case code == http.StatusTooManyRequests:
		return "429"
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	case code >= 200:
		return "2xx"
	default:
		return "1xx"
	}
}

type transport struct{ next http.RoundTripper }

// WrapTransport reports every request sent through next to Argvio (status,
// error class and duration) and returns its response and error unchanged. A
// nil next stands for http.DefaultTransport, looked up on each request.
func WrapTransport(next http.RoundTripper) http.RoundTripper {
	return &transport{next: next}
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	start := time.Now()
	resp, err := next.RoundTrip(req)
	ctx := req.Context()
	requestDuration.Record(ctx, time.Since(start))
	requests.Add(ctx, 1, StatusLabel(resp, err))
	if err != nil {
		requestErrors.Add(ctx, 1, ErrorClass(err))
	}
	return resp, err
}
