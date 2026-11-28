package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/reportx"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	tlscertificateexpired "github.com/cerberauth/vulnapi/scan/tls/certificate_expired"
	tlscertificatehostnamemismatch "github.com/cerberauth/vulnapi/scan/tls/certificate_hostname_mismatch"
	tlscertificateuntrusted "github.com/cerberauth/vulnapi/scan/tls/certificate_untrusted"
	tlscipherweak "github.com/cerberauth/vulnapi/scan/tls/cipher_weak"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
	tlsdrown "github.com/cerberauth/vulnapi/scan/tls/drown"
	tlsforwardsecrecymissing "github.com/cerberauth/vulnapi/scan/tls/forward_secrecy_missing"
	tlsheartbleed "github.com/cerberauth/vulnapi/scan/tls/heartbleed"
	tlshttpaccepted "github.com/cerberauth/vulnapi/scan/tls/http_accepted"
	tlsprotocoldeprecated "github.com/cerberauth/vulnapi/scan/tls/protocol_deprecated"
	tlsrobot "github.com/cerberauth/vulnapi/scan/tls/robot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const localIP = "127.0.0.1"

func selfSignedLeaf(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: localIP},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP(localIP)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func tlsServer(t *testing.T, config *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = config
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func runScan(t *testing.T, urls ...string) *reportx.Report {
	t.Helper()
	client := request.NewClient(request.NewClientOptions{InsecureSkipVerify: true})
	var operations operation.Operations
	for _, u := range urls {
		op, err := operation.NewOperation(http.MethodGet, u, nil, client)
		require.NoError(t, err)
		op.GenerateID()
		operations = append(operations, op)
	}
	s, err := scan.NewScan(harnessx.New(), operations, &scan.ScanOptions{})
	require.NoError(t, err)
	s.AddCheck(tlsfetch.Check, nil)
	s.AddCheck(tlshttpaccepted.Check, &tlshttpaccepted.Def)
	s.AddCheck(tlscertificateuntrusted.Check, &tlscertificateuntrusted.Def)
	s.AddCheck(tlscertificateexpired.Check, &tlscertificateexpired.Def)
	s.AddCheck(tlscertificatehostnamemismatch.Check, &tlscertificatehostnamemismatch.Def)
	s.AddCheck(tlsprotocoldeprecated.Check, &tlsprotocoldeprecated.Def)
	s.AddCheck(tlscipherweak.Check, &tlscipherweak.Def)
	s.AddCheck(tlsforwardsecrecymissing.Check, &tlsforwardsecrecymissing.Def)
	s.AddCheck(tlsheartbleed.Check, &tlsheartbleed.Def)
	s.AddCheck(tlsdrown.Check, &tlsdrown.Def)
	s.AddCheck(tlsrobot.Check, &tlsrobot.Def)

	report, errs, err := s.Execute(context.Background(), nil)
	require.NoError(t, err)
	require.Empty(t, errs)
	return report
}

func findingIDs(report *reportx.Report) []string {
	var ids []string
	for _, f := range report.Findings {
		ids = append(ids, f.ID)
	}
	return ids
}

func TestTLSChecks(t *testing.T) {
	now := time.Now()
	valid := selfSignedLeaf(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	expired := selfSignedLeaf(t, now.Add(-48*time.Hour), now.Add(-time.Hour))

	testCases := []struct {
		name     string
		config   *tls.Config
		host     string
		expected []string
		absent   []string
	}{
		{"self-signed", &tls.Config{Certificates: []tls.Certificate{valid}}, localIP, []string{"tls.certificate_untrusted"}, []string{"tls.certificate_expired", "tls.certificate_hostname_mismatch", "tls.protocol_deprecated", "tls.heartbleed", "tls.drown", "tls.robot"}},
		{"expired", &tls.Config{Certificates: []tls.Certificate{expired}}, localIP, []string{"tls.certificate_expired"}, []string{"tls.certificate_hostname_mismatch"}},
		{"wrong host", &tls.Config{Certificates: []tls.Certificate{valid}}, "localhost", []string{"tls.certificate_hostname_mismatch"}, []string{"tls.certificate_expired"}},
		{"TLS 1.0 allowed", &tls.Config{Certificates: []tls.Certificate{valid}, MinVersion: tls.VersionTLS10}, localIP, []string{"tls.protocol_deprecated"}, nil},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tlsServer(t, tc.config)

			report := runScan(t, strings.Replace(srv.URL, localIP, tc.host, 1)+"/users")

			ids := findingIDs(report)
			for _, id := range tc.expected {
				assert.Contains(t, ids, id)
			}
			for _, id := range tc.absent {
				assert.NotContains(t, ids, id)
			}
		})
	}
}

func TestTLSChecks_OneFindingPerHost(t *testing.T) {
	srv := tlsServer(t, &tls.Config{Certificates: []tls.Certificate{selfSignedLeaf(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour*24*90))}})

	report := runScan(t, srv.URL+"/users", srv.URL+"/orders", srv.URL+"/orders/1")

	var untrusted []reportx.Finding
	for _, f := range report.Findings {
		if f.ID == "tls.certificate_untrusted" {
			untrusted = append(untrusted, f)
		}
	}
	require.Len(t, untrusted, 1)
	assert.Equal(t, srv.URL, untrusted[0].Parameter)
	assert.Contains(t, untrusted[0].Extra["codes"], "certificate.self_signed")
}

func skipReasons(t *testing.T, urls ...string) map[harnessx.CheckID]string {
	t.Helper()
	client := request.NewClient(request.NewClientOptions{})
	var resources []harnessx.Resource
	for _, u := range urls {
		op, err := operation.NewOperation(http.MethodGet, u, nil, client)
		require.NoError(t, err)
		resources = append(resources, harnessx.Resource{ID: u, URL: u, Data: op})
	}
	store := harnessx.NewStaticResultStore(harnessx.Result{CheckID: scan.OperationsLoaderCheckID, Resources: resources})
	result, err := tlsfetch.Check.Run(context.Background(), harnessx.Target{}, store)
	require.NoError(t, err)
	require.NoError(t, result.Err)
	result.CheckID = tlsfetch.CheckID
	store = harnessx.NewStaticResultStore(harnessx.Result{CheckID: scan.OperationsLoaderCheckID, Resources: resources}, result)

	reasons := map[harnessx.CheckID]string{}
	for _, check := range []harnessx.Check{tlscertificateuntrusted.Check, tlsprotocoldeprecated.Check, tlscipherweak.Check, tlshttpaccepted.Check, tlsrobot.Check} {
		reasons[check.ID] = check.Skip.Eval(context.Background(), harnessx.Target{}, store)
	}
	return reasons
}

func TestTLSChecks_SkipReasons(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(plain.Close)
	closed, err := net.Listen("tcp", localIP+":0")
	require.NoError(t, err)
	closedAddr := closed.Addr().String()
	require.NoError(t, closed.Close())

	reasons := skipReasons(t, plain.URL+"/users")
	assert.Contains(t, reasons["tls.certificate_untrusted"], "target URL uses plain HTTP")
	assert.Contains(t, reasons["tls.http_accepted"], "target is not HTTPS")

	reasons = skipReasons(t, "https://"+closedAddr+"/users")
	assert.Contains(t, reasons["tls.certificate_untrusted"], "target port is closed or unreachable")
	assert.Contains(t, reasons["tls.protocol_deprecated"], "target port is closed or unreachable")
	assert.Contains(t, reasons["tls.robot"], "target port is closed or unreachable")
}
