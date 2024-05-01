package bestpractices

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPCookiesScanID   = "best_practices.http_cookies"
	HTTPCookiesScanName = "HTTP Cookies Best Practices"

	HTTPCookiesNotHTTPOnlySeverityLevel     = 0
	HTTPCookiesNotHTTPOnlyOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTTPCookiesNotHTTPOnlyVulnerabilityID   = "security_misconfiguration.http_cookies_not_http_only"
	HTTPCookiesNotHTTPOnlyVulnerabilityName = "Cookies not HTTP-Only"
	HTTPCookiesNotHTTPOnlyVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"

	HTTPCookiesNotSecureSeverityLevel     = 0
	HTTPCookiesNotSecureOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTTPCookiesNotSecureVulnerabilityID   = "security_misconfiguration.http_cookies_not_secure"
	HTTPCookiesNotSecureVulnerabilityName = "Cookies not Secure"
	HTTPCookiesNotSecureVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"

	HTTPCookiesSameSiteSeverityLevel     = 0
	HTTPCookiesSameSiteOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTTPCookiesSameSiteVulnerabilityID   = "security_misconfiguration.http_cookies_same_site"
	HTTPCookiesSameSiteVulnerabilityName = "Cookies SameSite not set or set to None"
	HTTPCookiesSameSiteVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value"

	HTTPCookiesExpiresSeverityLevel     = 0
	HTTPCookiesExpiresOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTTPCookiesExpiresVulnerabilityID   = "security_misconfiguration.http_cookies_expires"
	HTTPCookiesExpiresVulnerabilityName = "Cookies Expires not set"
	HTTPCookiesExpiresVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"
)

func HTTPCookiesScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(HTTPCookiesScanID, HTTPCookiesScanName)

	securityScheme.SetAttackValue(securityScheme.GetValidValue())
	attempt, err := scan.ScanURL(operation, &securityScheme)
	r.AddScanAttempt(attempt).End()
	if err != nil {
		return r, err
	}

	// Detect every cookies insecure practices
	for _, cookie := range attempt.Response.Cookies() {
		if !cookie.Secure {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesNotSecureSeverityLevel,

				OWASP2023Category: HTTPCookiesNotSecureOWASP2023Category,

				ID:   HTTPCookiesNotSecureVulnerabilityID,
				Name: HTTPCookiesNotSecureVulnerabilityName,
				URL:  HTTPCookiesNotSecureVulnerabilityURL,

				Operation: operation,
			})
		}

		if !cookie.HttpOnly {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesNotHTTPOnlySeverityLevel,

				OWASP2023Category: HTTPCookiesNotHTTPOnlyOWASP2023Category,

				ID:   HTTPCookiesNotHTTPOnlyVulnerabilityID,
				Name: HTTPCookiesNotHTTPOnlyVulnerabilityName,
				URL:  HTTPCookiesNotHTTPOnlyVulnerabilityURL,

				Operation: operation,
			})
		}

		if cookie.SameSite == http.SameSiteNoneMode {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesSameSiteSeverityLevel,

				OWASP2023Category: HTTPCookiesSameSiteOWASP2023Category,

				ID:   HTTPCookiesSameSiteVulnerabilityID,
				Name: HTTPCookiesSameSiteVulnerabilityName,
				URL:  HTTPCookiesSameSiteVulnerabilityURL,

				Operation: operation,
			})
		}

		if cookie.Expires.IsZero() {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesExpiresSeverityLevel,

				OWASP2023Category: HTTPCookiesExpiresOWASP2023Category,

				ID:   HTTPCookiesExpiresVulnerabilityID,
				Name: HTTPCookiesExpiresVulnerabilityName,
				URL:  HTTPCookiesExpiresVulnerabilityURL,

				Operation: operation,
			})
		}
	}

	return r, nil
}
