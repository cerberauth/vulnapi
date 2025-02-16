package httpheaders

import (
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
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

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	attempt, err := scan.ScanURL(op, securityScheme)
	r := report.NewScanReport(HTTPHeadersScanID, HTTPHeadersScanName, op)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt)

	contentOptionsMissing := report.NewIssueReport(contentOptionsMissingIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	corsMissing := report.NewIssueReport(corsMissingIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	corsWildcard := report.NewIssueReport(corsWildcardIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	cspFrameAncestorsMissing := report.NewIssueReport(cspFrameAncestorsMissingIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	cspMissing := report.NewIssueReport(cspMissingIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	frameOptionsMissing := report.NewIssueReport(frameOptionsMissingIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	hstsMissing := report.NewIssueReport(hstsMissingIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)

	r.AddIssueReport(contentOptionsMissing)
	r.AddIssueReport(corsMissing)
	r.AddIssueReport(corsWildcard)
	r.AddIssueReport(cspFrameAncestorsMissing)
	r.AddIssueReport(cspMissing)
	r.AddIssueReport(frameOptionsMissing)
	r.AddIssueReport(hstsMissing)

	cspHeader := attempt.Response.GetHeader().Get(CSPHTTPHeader)
	cspMissing.WithBooleanStatus(cspHeader != "")
	cspFrameAncestorsMissing.WithBooleanStatus(CheckCSPFrameAncestors(cspHeader))

	allowOrigin := attempt.Response.GetHeader().Get(CORSOriginHTTPHeader)
	isCorsMissing := allowOrigin == ""
	corsMissing.WithBooleanStatus(!isCorsMissing)
	if isCorsMissing {
		corsWildcard.Skip()
	} else {
		corsWildcard.WithBooleanStatus(allowOrigin != "*")
	}

	hstsMissing.WithBooleanStatus(attempt.Response.GetHeader().Get(HSTSHTTPHeader) != "")
	contentOptionsMissing.WithBooleanStatus(attempt.Response.GetHeader().Get(XContentTypeOptionsHTTPHeader) != "")
	frameOptionsMissing.WithBooleanStatus(attempt.Response.GetHeader().Get(XFrameOptionsHTTPHeader) != "")

	attempt.WithBooleanStatus(!r.HasFailedIssueReport())
	return r.End(), nil
}
