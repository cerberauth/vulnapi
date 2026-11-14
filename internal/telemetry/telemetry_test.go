package telemetry_test

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"

	"github.com/cerberauth/vulnapi/internal/telemetry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorClass(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"canceled", context.Canceled, telemetry.ReasonCanceled},
		{"deadline", context.DeadlineExceeded, telemetry.ReasonTimeout},
		{"wrapped deadline", &url.Error{Op: "Get", URL: "https://secret.example/path", Err: context.DeadlineExceeded}, telemetry.ReasonTimeout},
		{"dns", &net.DNSError{Err: "no such host", Name: "secret.example"}, telemetry.ReasonDNS},
		{"refused", &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, telemetry.ReasonRefused},
		{"reset", fmt.Errorf("read: %w", syscall.ECONNRESET), telemetry.ReasonReset},
		{"eof", io.EOF, telemetry.ReasonReset},
		{"unknown authority", x509.UnknownAuthorityError{}, telemetry.ReasonTLS},
		{"hostname", x509.HostnameError{Host: "secret.example"}, telemetry.ReasonTLS},
		{"other", errors.New("something about secret.example"), telemetry.ReasonOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, telemetry.ErrorClass(tt.err))
		})
	}
}

func TestStatusLabel(t *testing.T) {
	for code, want := range map[int]string{
		100: "1xx", 200: "2xx", 204: "2xx", 301: "3xx", 400: "4xx", 404: "4xx",
		401: "401", 403: "403", 429: "429", 500: "5xx", 503: "5xx",
	} {
		assert.Equal(t, want, telemetry.StatusLabel(&http.Response{StatusCode: code}, nil), "status %d", code)
	}
	assert.Equal(t, "error", telemetry.StatusLabel(nil, errors.New("boom")))
	assert.Equal(t, "error", telemetry.StatusLabel(nil, nil))
}

func TestWrapTransportPassesThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()

	// A nil transport falls back to http.DefaultTransport.
	client := &http.Client{Transport: telemetry.WrapTransport(nil)}
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)

	// A transport error comes back unchanged.
	wantErr := errors.New("round trip failed")
	failing := &http.Client{Transport: telemetry.WrapTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}))}
	_, err = failing.Get(srv.URL)
	assert.ErrorIs(t, err, wantErr)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
