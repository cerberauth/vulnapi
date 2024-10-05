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
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	httpcookies "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies"
	httpheaders "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers"
	httptrace "github.com/cerberauth/vulnapi/scan/misconfiguration/http_trace"
	httptrack "github.com/cerberauth/vulnapi/scan/misconfiguration/http_track"
)

func WithAllCommonScans(s *scan.Scan) *scan.Scan {
	s.AddScanHandler(scan.NewOperationScanHandler(fingerprint.DiscoverFingerPrintScanID, fingerprint.ScanHandler))

	s.AddOperationScanHandler(scan.NewOperationScanHandler(acceptunauthenticated.NoAuthOperationScanID, acceptunauthenticated.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(authenticationbypass.AcceptsUnauthenticatedOperationScanID, authenticationbypass.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(algnone.AlgNoneJwtScanID, algnone.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(blanksecret.BlankSecretVulnerabilityScanID, blanksecret.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(notverified.NotVerifiedJwtScanID, notverified.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(nullsignature.NullSignatureScanID, nullsignature.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(weaksecret.WeakSecretVulnerabilityScanID, weaksecret.ScanHandler))

	s.AddOperationScanHandler(scan.NewOperationScanHandler(httpcookies.HTTPCookiesScanID, httpcookies.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httpheaders.HTTPHeadersScanID, httpheaders.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httptrace.HTTPTraceScanID, httptrace.ScanHandler))
	s.AddOperationScanHandler(scan.NewOperationScanHandler(httptrack.HTTPTrackScanID, httptrack.ScanHandler))

	return s
}
