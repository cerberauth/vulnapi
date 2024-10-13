package httpheaders

import (
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
	HTTPHeadersScanID   = "misconfiguration.http_headers"
	HTTPHeadersScanName = "HTTP Headers Misconfiguration"
)

var contentOptionsMissingIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_content_options_missing",
	Name: "X-Content-Type-Options Header is missing",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_16_Configuration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var corsMissingIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_cors_missing",
	Name: "CORS Headers are missing",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_942_Overly_Permissive_CORS_Policy,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   5.1,
	},
}

var corsWildcardIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_cors_wildcard",
	Name: "CORS Allow-Origin Header is set to wildcard (*)",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_942_Overly_Permissive_CORS_Policy,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var cspFrameAncestorsMissingIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_csp_frame_ancestors_missing",
	Name: "CSP frame-ancestors policy is not set",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_1021_Improper_Restriction_Rendered_UI,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
		Score:   5.1,
	},
}

var frameOptionsMissingIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_frame_options_missing",
	Name: "X-Frame-Options Header is missing",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_1021_Improper_Restriction_Rendered_UI,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
		Score:   5.1,
	},
}

var cspMissingIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_csp_missing",
	Name: "CSP Header is not set",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_1021_Improper_Restriction_Rendered_UI,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var hstsMissingIssue = report.Issue{
	ID:   "security_misconfiguration.http_headers_hsts_missing",
	Name: "HSTS Header is missing",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_16_Configuration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

func CheckCSPFrameAncestors(cspHeader string) bool {
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

	return false
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	contentOptionsMissing := report.NewIssueReport(contentOptionsMissingIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	corsMissing := report.NewIssueReport(corsMissingIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	corsWildcard := report.NewIssueReport(corsWildcardIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	cspFrameAncestorsMissing := report.NewIssueReport(cspFrameAncestorsMissingIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	cspMissing := report.NewIssueReport(cspMissingIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	frameOptionsMissing := report.NewIssueReport(frameOptionsMissingIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	hstsMissing := report.NewIssueReport(hstsMissingIssue).WithOperation(operation).WithSecurityScheme(securityScheme)

	attempt, err := scan.ScanURL(operation, &securityScheme)
	r := report.NewScanReport(HTTPHeadersScanID, HTTPHeadersScanName, operation)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt).End()

	cspHeader := attempt.Response.Header.Get(CSPHTTPHeader)
	r.AddIssueReport(cspMissing.Clone().WithBooleanStatus(cspHeader != ""))
	r.AddIssueReport(cspFrameAncestorsMissing.Clone().WithBooleanStatus(CheckCSPFrameAncestors(cspHeader)))

	allowOrigin := attempt.Response.Header.Get(CORSOriginHTTPHeader)

	isCorsMissing := allowOrigin == ""
	r.AddIssueReport(corsMissing.Clone().WithBooleanStatus(!isCorsMissing))
	if isCorsMissing {
		r.AddIssueReport(corsWildcard.Clone().Skip())
	} else {
		r.AddIssueReport(corsWildcard.Clone().WithBooleanStatus(allowOrigin != "*"))
	}

	r.AddIssueReport(hstsMissing.Clone().WithBooleanStatus(attempt.Response.Header.Get(HSTSHTTPHeader) != ""))
	r.AddIssueReport(contentOptionsMissing.Clone().WithBooleanStatus(attempt.Response.Header.Get(XContentTypeOptionsHTTPHeader) != ""))
	r.AddIssueReport(frameOptionsMissing.Clone().WithBooleanStatus(attempt.Response.Header.Get(XFrameOptionsHTTPHeader) != ""))

	return r, nil
}
