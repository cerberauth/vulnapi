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
	httpOnlyVulnReport := report.NewVulnerabilityReport(httpNotHttpOnlyIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	notSecureVulnReport := report.NewVulnerabilityReport(notSecureIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	sameSiteNoneVulnReport := report.NewVulnerabilityReport(sameSiteNoneIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	withoutSameSiteVulnReport := report.NewVulnerabilityReport(withoutSameSiteIssue).WithOperation(operation).WithSecurityScheme(securityScheme)
	withoutExpiresVulnReport := report.NewVulnerabilityReport(withoutExpiresIssue).WithOperation(operation).WithSecurityScheme(securityScheme)

	attempt, err := scan.ScanURL(operation, &securityScheme)
	r := report.NewScanReport(HTTPCookiesScanID, HTTPCookiesScanName, operation)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attempt).End()

	// Detect every cookies insecure practices
	for _, cookie := range attempt.Response.Cookies() {
		r.AddVulnerabilityReport(notSecureVulnReport.Clone().WithBooleanStatus(cookie.Secure))
		r.AddVulnerabilityReport(httpOnlyVulnReport.Clone().WithBooleanStatus(cookie.HttpOnly))
		r.AddVulnerabilityReport(sameSiteNoneVulnReport.Clone().WithBooleanStatus(cookie.SameSite != http.SameSiteNoneMode))
		r.AddVulnerabilityReport(withoutSameSiteVulnReport.Clone().WithBooleanStatus(cookie.SameSite != 0))
		r.AddVulnerabilityReport(withoutExpiresVulnReport.Clone().WithBooleanStatus(!cookie.Expires.IsZero()))
	}

	if len(attempt.Response.Cookies()) == 0 {
		r.AddVulnerabilityReport(notSecureVulnReport.Clone().Skip())
		r.AddVulnerabilityReport(httpOnlyVulnReport.Clone().Skip())
		r.AddVulnerabilityReport(sameSiteNoneVulnReport.Clone().Skip())
		r.AddVulnerabilityReport(withoutSameSiteVulnReport.Clone().Skip())
		r.AddVulnerabilityReport(withoutExpiresVulnReport.Clone().Skip())
	}

	return r, nil
}
