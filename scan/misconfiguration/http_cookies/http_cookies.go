package httpcookies

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPCookiesScanID   = "misconfiguration.http_cookies"
	HTTPCookiesScanName = "HTTP Cookies Misconfiguration"
)

var httpNotHttpOnlyIssue = report.Issue{
	ID:   "security_misconfiguration.http_cookies_not_http_only",
	Name: "Cookies not HTTP-Only",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_1004_Sensitive_Cookie_Without_Http_Only,
		CAPEC: report.CAPEC_31_Manipulating_HTTP_Cookies,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var notSecureIssue = report.Issue{
	ID:   "security_misconfiguration.http_cookies_not_secure",
	Name: "Cookies not Secure",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_614_Sensitive_Cookie_Without_Secure_Flag,
		CAPEC: report.CAPEC_31_Manipulating_HTTP_Cookies,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var sameSiteNoneIssue = report.Issue{
	ID:   "security_misconfiguration.http_cookies_same_site_none",
	Name: "Cookies SameSite set to None",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_1275_Sensitive_Cookie_With_Improper_SameSite,
		CAPEC: report.CAPEC_31_Manipulating_HTTP_Cookies,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var withoutSameSiteIssue = report.Issue{
	ID:   "security_misconfiguration.http_cookies_without_same_site",
	Name: "Cookies SameSite not set",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_1275_Sensitive_Cookie_With_Improper_SameSite,
		CAPEC: report.CAPEC_31_Manipulating_HTTP_Cookies,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var withoutExpiresIssue = report.Issue{
	ID:   "security_misconfiguration.http_cookies_without_expires",
	Name: "Cookies Expires not set",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_613_Insufficient_Session_Expiration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	attempt, err := scan.ScanURL(op, securityScheme)
	r := report.NewScanReport(HTTPCookiesScanID, HTTPCookiesScanName, op)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt)

	httpOnlyVulnReport := report.NewIssueReport(httpNotHttpOnlyIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	notSecureVulnReport := report.NewIssueReport(notSecureIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	sameSiteNoneVulnReport := report.NewIssueReport(sameSiteNoneIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	withoutSameSiteVulnReport := report.NewIssueReport(withoutSameSiteIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)
	withoutExpiresVulnReport := report.NewIssueReport(withoutExpiresIssue).WithOperation(op).WithSecurityScheme(securityScheme).WithScanAttempt(attempt)

	r.AddIssueReport(httpOnlyVulnReport)
	r.AddIssueReport(notSecureVulnReport)
	r.AddIssueReport(sameSiteNoneVulnReport)
	r.AddIssueReport(withoutSameSiteVulnReport)
	r.AddIssueReport(withoutExpiresVulnReport)

	if len(attempt.Response.GetCookies()) == 0 {
		notSecureVulnReport.Skip()
		httpOnlyVulnReport.Skip()
		sameSiteNoneVulnReport.Skip()
		withoutSameSiteVulnReport.Skip()
		withoutExpiresVulnReport.Skip()
	}

	// Detect every cookies insecure practices
	for _, cookie := range attempt.Response.GetCookies() {
		notSecureVulnReport.WithBooleanStatus(cookie.Secure)
		httpOnlyVulnReport.WithBooleanStatus(cookie.HttpOnly)
		sameSiteNoneVulnReport.WithBooleanStatus(cookie.SameSite != http.SameSiteNoneMode)
		withoutSameSiteVulnReport.WithBooleanStatus(cookie.SameSite != 0)
		withoutExpiresVulnReport.WithBooleanStatus(!cookie.Expires.IsZero())
	}

	attempt.WithBooleanStatus(!r.HasFailedIssueReport())
	return r.End(), nil
}
