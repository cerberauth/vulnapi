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
	HTTPHeadersScanID   = "best_practices.http_headers"
	HTTPHeadersScanName = "HTTP Headers Best Practices"

	CSPHTTPHeaderIsNotSetSeverityLevel     = 0
	CSPHTTPHeaderISNotSetOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	CSPHTTPHeaderIsNotSetVulnerabilityID   = "security_misconfiguration.http_headers_csp_not_set"
	CSPHTTPHeaderIsNotSetVulnerabilityName = "CSP Header is not set"
	CSPHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"

	CSPHTTPHeaderFrameAncestorsIsNotSetSeverityLevel     = 0
	CSPHTTPHeaderFrameAncestorsIsNotSetOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityID   = "security_misconfiguration.http_headers_csp_frame_ancestors_not_set"
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName = "CSP frame-ancestors policy is not set"
	CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"

	HTSTHTTPHeaderIsNotSetSeverityLevel     = 0
	HTSTHTTPHeaderIsNotSetOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTSTHTTPHeaderIsNotSetVulnerabilityID   = "security_misconfiguration.http_headers_hsts_not_set"
	HSTSHTTPHeaderIsNotSetVulnerabilityName = "HSTS Header is not set"
	HSTSHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"

	CORSHTTPHeaderIsNotSetSeverityLevel     = 0
	CORSHTTPHeaderIsNotSetOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	CORSHTTPHeaderIsNotSetVulnerabilityID   = "security_misconfiguration.http_headers_cors_not_set"
	CORSHTTPHeaderIsNotSetVulnerabilityName = "CORS Headers are not set"
	CORSHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"

	CORSHTTPHeaderIsPermisiveSeverityLevel     = 0
	CORSHTTPHeaderIsPermisiveOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	CORSHTTPHeaderIsPermisiveVulnerabilityID   = "security_misconfiguration.http_headers_cors_permissive"
	CORSHTTPHeaderIsPermisiveVulnerabilityName = "CORS Header is set but permissive"
	CORSHTTPHeaderIsPermisiveVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin"

	XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel     = 0
	XContentTypeOptionsHTTPHeaderIsNotSetOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityID   = "security_misconfiguration.http_headers_x_content_type_options_not_set"
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName = "X-Content-Type-Options Header is not set"
	XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"

	XFrameOptionsHTTPHeaderIsNotSetSeverityLevel     = 0
	XFrameOptionsHTTPHeaderIsNotSetOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityID   = "security_misconfiguration.http_headers_x_frame_options_not_set"
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName = "X-Frame-Options Header is not set"
	XFrameOptionsHTTPHeaderIsNotSetVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
)

func checkCSPHeader(operation *request.Operation, headers http.Header, r *report.ScanReport) bool {
	cspHeader := headers.Get(CSPHTTPHeader)
	if cspHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: CSPHTTPHeaderIsNotSetSeverityLevel,

			OWASP2023Category: CSPHTTPHeaderISNotSetOWASP2023Category,

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

		OWASP2023Category: CSPHTTPHeaderFrameAncestorsIsNotSetOWASP2023Category,

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

			OWASP2023Category: CORSHTTPHeaderIsNotSetOWASP2023Category,

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

		OWASP2023Category: CORSHTTPHeaderIsPermisiveOWASP2023Category,

		ID:   CORSHTTPHeaderIsPermisiveVulnerabilityID,
		Name: CORSHTTPHeaderIsPermisiveVulnerabilityName,
		URL:  CORSHTTPHeaderIsPermisiveVulnerabilityURL,

		Operation: operation,
	})

	return false
}

func HTTPHeadersBestPracticesScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	if ss.HasValidValue() {
		ss.SetAttackValue(ss.GetValidValue())
	}

	vsa, err := scan.ScanURL(operation, &ss)
	r := report.NewScanReport(HTTPHeadersScanID, HTTPHeadersScanName)
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

			OWASP2023Category: HTSTHTTPHeaderIsNotSetOWASP2023Category,

			ID:   HTSTHTTPHeaderIsNotSetVulnerabilityID,
			Name: HSTSHTTPHeaderIsNotSetVulnerabilityName,
			URL:  HSTSHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})
	}

	if xContentTypeOptionsHeader := vsa.Response.Header.Get(XContentTypeOptionsHTTPHeader); xContentTypeOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel,

			OWASP2023Category: XContentTypeOptionsHTTPHeaderIsNotSetOWASP2023Category,

			ID:   XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityID,
			Name: XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
			URL:  XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})
	}

	if xFrameOptionsHeader := vsa.Response.Header.Get(XFrameOptionsHTTPHeader); xFrameOptionsHeader == "" {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: XFrameOptionsHTTPHeaderIsNotSetSeverityLevel,

			OWASP2023Category: XFrameOptionsHTTPHeaderIsNotSetOWASP2023Category,

			ID:   XFrameOptionsHTTPHeaderIsNotSetVulnerabilityID,
			Name: XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
			URL:  XFrameOptionsHTTPHeaderIsNotSetVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
