package httpcookies

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
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

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	httpOnlyVulnReport := report.NewIssueReport(httpNotHttpOnlyIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	notSecureVulnReport := report.NewIssueReport(notSecureIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	sameSiteNoneVulnReport := report.NewIssueReport(sameSiteNoneIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	withoutSameSiteVulnReport := report.NewIssueReport(withoutSameSiteIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	withoutExpiresVulnReport := report.NewIssueReport(withoutExpiresIssue).WithOperation(operation).WithSecurityScheme(securityScheme)

	attempt, err := scan.ScanURL(operation, &securityScheme)
	r := report.NewScanReport(HTTPCookiesScanID, HTTPCookiesScanName, operation)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt).End()

	// Detect every cookies insecure practices
	for _, cookie := range attempt.Response.Cookies() {
		r.AddIssueReport(notSecureVulnReport.Clone().WithBooleanStatus(cookie.Secure))
		r.AddIssueReport(httpOnlyVulnReport.Clone().WithBooleanStatus(cookie.HttpOnly))
		r.AddIssueReport(sameSiteNoneVulnReport.Clone().WithBooleanStatus(cookie.SameSite != http.SameSiteNoneMode))
		r.AddIssueReport(withoutSameSiteVulnReport.Clone().WithBooleanStatus(cookie.SameSite != 0))
		r.AddIssueReport(withoutExpiresVulnReport.Clone().WithBooleanStatus(!cookie.Expires.IsZero()))
	}

	if len(attempt.Response.Cookies()) == 0 {
		r.AddIssueReport(notSecureVulnReport.Clone().Skip())
		r.AddIssueReport(httpOnlyVulnReport.Clone().Skip())
		r.AddIssueReport(sameSiteNoneVulnReport.Clone().Skip())
		r.AddIssueReport(withoutSameSiteVulnReport.Clone().Skip())
		r.AddIssueReport(withoutExpiresVulnReport.Clone().Skip())
	}

	return r, nil
}
