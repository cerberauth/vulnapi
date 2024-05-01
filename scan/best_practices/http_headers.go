package bestpractices

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	CSPHTTPHeader                 = "Content-Security-Policy"
	HSTSHTTPHeader                = "Strict-Transport-Security"
	CORSOriginHTTPHeader          = "Access-Control-Allow-Origin"
	XContentTypeOptionsHTTPHeader = "X-Content-Type-Options"
	XFrameOptionsHTTPHeader       = "X-Frame-Options"
)

const (
	HTTPHeadersScanID   = "bestpractices.http-headers"
	HTTPHeadersScanName = "HTTP Headers Best Practices"

	CSPHTTPHeaderIsNotSetSeverityLevel     = 0
	CSPHTTPHeaderIsNotSetVulnerabilityID   = "bestpractices.http-headers-csp-not-set"
	CSPHTTPHeaderIsNotSetVulnerabilityName = "CSP Header is not set"
	CSPHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"

	CSPHTTPHeaderFrameAncestorsIsNotSetSeverityLevel     = 0
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityID   = "bestpractices.http-headers-csp-frame-ancestors-not-set"
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName = "CSP frame-ancestors policy is not set"
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"

	HTSTHTTPHeaderIsNotSetSeverityLevel     = 0
	HTSTHTTPHeaderIsNotSetVulnerabilityID   = "bestpractices.http-headers-hsts-not-set"
	HSTSHTTPHeaderIsNotSetVulnerabilityName = "HSTS Header is not set"
	HSTSHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"

	CORSHTTPHeaderIsNotSetSeverityLevel     = 0
	CORSHTTPHeaderIsNotSetVulnerabilityID   = "bestpractices.http-headers-cors-not-set"
	CORSHTTPHeaderIsNotSetVulnerabilityName = "CORS Header is not set"
	CORSHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"

	CORSHTTPHeaderIsPermisiveSeverityLevel     = 0
	CORSHTTPHeaderIsPermisiveVulnerabilityID   = "bestpractices.http-headers-cors-permissive"
	CORSHTTPHeaderIsPermisiveVulnerabilityName = "CORS Header is set but permissive"
	CORSHTTPHeaderIsPermisiveVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"

	XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel     = 0
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityID   = "bestpractices.http-headers-x-content-type-options-not-set"
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName = "X-Content-Type-Options Header is not set"
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"

	XFrameOptionsHTTPHeaderIsNotSetSeverityLevel     = 0
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityID   = "bestpractice.http-headers-x-frame-options-not-set"
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName = "X-Frame-Options Header is not set"
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
)

func checkCSPHeader(operation *request.Operation, headers http.Header, r *report.ScanReport) bool {
	cspHeader := headers.Get(CSPHTTPHeader)
	if cspHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CSPHTTPHeaderIsNotSetSeverityLevel,

			ID:   CSPHTTPHeaderIsNotSetVulnerabilityID,
			Name: CSPHTTPHeaderIsNotSetVulnerabilityName,
			URL:  CSPHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})

		return false
	}

	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "frame-ancestors") {
			// Check if frame-ancestors directive is not equal to "none"
			if strings.Contains(directive, "none") {
				return true
			}
		}
	}

	r.AddVulnerabilityReport(&report.VulnerabilityReport{
		SeverityLevel: CSPHTTPHeaderFrameAncestorsIsNotSetSeverityLevel,

		ID:   CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityID,
		Name: CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		URL:  CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityURL,

		Operation: operation,
	})

	return false
}

func CheckCORSAllowOrigin(operation *request.Operation, headers http.Header, r *report.ScanReport) bool {
	allowOrigin := headers.Get(CORSOriginHTTPHeader)
	if allowOrigin == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CORSHTTPHeaderIsNotSetSeverityLevel,

			ID:   CORSHTTPHeaderIsNotSetVulnerabilityID,
			Name: CORSHTTPHeaderIsNotSetVulnerabilityName,
			URL:  CORSHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})

		return false
	}

	// Check if the Access-Control-Allow-Origin header is not "*" (wildcard)
	if allowOrigin != "*" {
		return true
	}

	r.AddVulnerabilityReport(&report.VulnerabilityReport{
		SeverityLevel: CORSHTTPHeaderIsPermisiveSeverityLevel,

		ID:   CORSHTTPHeaderIsPermisiveVulnerabilityID,
		Name: CORSHTTPHeaderIsPermisiveVulnerabilityName,
		URL:  CORSHTTPHeaderIsPermisiveVulnerabilityURL,

		Operation: operation,
	})

	return false
}

func HTTPHeadersBestPracticesScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(HTTPHeadersScanID, HTTPHeadersScanName)

	ss.SetAttackValue(ss.GetValidValue())
	vsa, err := scan.ScanURL(operation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Err != nil {
		return r, vsa.Err
	}

	checkCSPHeader(operation, vsa.Response.Header, r)
	CheckCORSAllowOrigin(operation, vsa.Response.Header, r)

	if hstsHeader := vsa.Response.Header.Get(HSTSHTTPHeader); hstsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HTSTHTTPHeaderIsNotSetSeverityLevel,

			ID:   HTSTHTTPHeaderIsNotSetVulnerabilityID,
			Name: HSTSHTTPHeaderIsNotSetVulnerabilityName,
			URL:  HSTSHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})
	}

	if xContentTypeOptionsHeader := vsa.Response.Header.Get(XContentTypeOptionsHTTPHeader); xContentTypeOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel,

			ID:   XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityID,
			Name: XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
			URL:  XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})
	}

	if xFrameOptionsHeader := vsa.Response.Header.Get(XFrameOptionsHTTPHeader); xFrameOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XFrameOptionsHTTPHeaderIsNotSetSeverityLevel,

			ID:   XFrameOptionsHTTPHeaderIsNotSetVulnerabilityID,
			Name: XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
			URL:  XFrameOptionsHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
