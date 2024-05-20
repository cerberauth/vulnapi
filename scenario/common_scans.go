package scenario

import (
	"github.com/cerberauth/vulnapi/scan"
	authenticationbypass "github.com/cerberauth/vulnapi/scan/broken_authentication/authentication_bypass"
	algnone "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/alg_none"
	blanksecret "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/blank_secret"
	notverified "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/not_verified"
	nullsignature "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/null_signature"
	weaksecret "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/weak_secret"
	acceptunauthenticated "github.com/cerberauth/vulnapi/scan/discover/accept_unauthenticated"
	serversignature "github.com/cerberauth/vulnapi/scan/discover/server_signature"
	httpcookies "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies"
	httpheaders "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers"
	httptrace "github.com/cerberauth/vulnapi/scan/misconfiguration/http_trace"
	httptrack "github.com/cerberauth/vulnapi/scan/misconfiguration/http_track"
)

func WithAllCommonScans(s *scan.Scan) *scan.Scan {
	s.AddScanHandler(serversignature.ScanHandler)
	s.AddOperationScanHandler(acceptunauthenticated.ScanHandler)

	s.AddOperationScanHandler(authenticationbypass.ScanHandler)
	s.AddOperationScanHandler(algnone.ScanHandler)
	s.AddOperationScanHandler(blanksecret.ScanHandler)
	s.AddOperationScanHandler(notverified.ScanHandler)
	s.AddOperationScanHandler(nullsignature.ScanHandler)
	s.AddOperationScanHandler(weaksecret.ScanHandler)

	s.AddOperationScanHandler(httpcookies.ScanHandler)
	s.AddOperationScanHandler(httpheaders.ScanHandler)
	s.AddOperationScanHandler(httptrace.ScanHandler)
	s.AddOperationScanHandler(httptrack.ScanHandler)

	return s
}
