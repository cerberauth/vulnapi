package scenario

import (
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	authenticationbypass "github.com/cerberauth/vulnapi/scan/broken_authentication/authentication_bypass"
	algnone "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/alg_none"
	blanksecret "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/blank_secret"
	notverified "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/not_verified"
	nullsignature "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/null_signature"
	weaksecret "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/weak_secret"
	acceptunauthenticated "github.com/cerberauth/vulnapi/scan/discover/accept_unauthenticated"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	httpcookies "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies"
	httpheaders "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers"
	httpmethodoverride "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override"
	httptrace "github.com/cerberauth/vulnapi/scan/misconfiguration/http_trace"
	httptrack "github.com/cerberauth/vulnapi/scan/misconfiguration/http_track"
)

func WithAllCommonScans(s *scan.Scan) *scan.Scan {
	s.AddScanHandler(scan.NewOperationScanHandler(fingerprint.DiscoverFingerPrintScanID, fingerprint.ScanHandler, []report.Issue{}))

	s.AddOperationScanHandler(scan.NewOperationScanHandler(acceptunauthenticated.NoAuthOperationScanID, acceptunauthenticated.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(authenticationbypass.AcceptsUnauthenticatedOperationScanID, authenticationbypass.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(algnone.AlgNoneJwtScanID, algnone.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(blanksecret.BlankSecretVulnerabilityScanID, blanksecret.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(notverified.NotVerifiedJwtScanID, notverified.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(nullsignature.NullSignatureScanID, nullsignature.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(weaksecret.WeakSecretVulnerabilityScanID, weaksecret.ScanHandler, []report.Issue{}))

	s.AddOperationScanHandler(scan.NewOperationScanHandler(httpcookies.HTTPCookiesScanID, httpcookies.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httpheaders.HTTPHeadersScanID, httpheaders.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httpmethodoverride.HTTPMethodOverrideScanID, httpmethodoverride.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httptrace.HTTPTraceScanID, httptrace.ScanHandler, []report.Issue{}))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httptrack.HTTPTrackScanID, httptrack.ScanHandler, []report.Issue{}))

	return s
}
