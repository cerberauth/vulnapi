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
	attempt, err := scan.ScanURL(operation, &securityScheme)
	r := report.NewScanReport(HTTPCookiesScanID, HTTPCookiesScanName, operation)
	r.AddScanAttempt(attempt).End()
	if err != nil {
		return r, err
	}

	// Detect every cookies insecure practices
	for _, cookie := range attempt.Response.Cookies() {
		r.AddVulnerabilityReport(report.NewVulnerabilityReport(
			HTTPCookiesNotSecureSeverityLevel,
			HTTPCookiesNotSecureOWASP2023Category,
			HTTPCookiesNotSecureVulnerabilityID,
			HTTPCookiesNotSecureVulnerabilityName,
			HTTPCookiesNotSecureVulnerabilityURL,
		).WithOperation(operation).WithSecurityScheme(securityScheme).WithBooleanStatus(cookie.Secure))

		r.AddVulnerabilityReport(report.NewVulnerabilityReport(
			HTTPCookiesNotHTTPOnlySeverityLevel,
			HTTPCookiesNotHTTPOnlyOWASP2023Category,
			HTTPCookiesNotHTTPOnlyVulnerabilityID,
			HTTPCookiesNotHTTPOnlyVulnerabilityName,
			HTTPCookiesNotHTTPOnlyVulnerabilityURL,
		).WithOperation(operation).WithSecurityScheme(securityScheme).WithBooleanStatus(cookie.HttpOnly))

		r.AddVulnerabilityReport(report.NewVulnerabilityReport(
			HTTPCookiesSameSiteSeverityLevel,
			HTTPCookiesSameSiteOWASP2023Category,
			HTTPCookiesSameSiteVulnerabilityID,
			HTTPCookiesSameSiteVulnerabilityName,
			HTTPCookiesSameSiteVulnerabilityURL,
		).WithOperation(operation).WithSecurityScheme(securityScheme).WithBooleanStatus(cookie.SameSite != http.SameSiteNoneMode))

		r.AddVulnerabilityReport(report.NewVulnerabilityReport(
			HTTPCookiesExpiresSeverityLevel,
			HTTPCookiesExpiresOWASP2023Category,
			HTTPCookiesExpiresVulnerabilityID,
			HTTPCookiesExpiresVulnerabilityName,
			HTTPCookiesExpiresVulnerabilityURL,
		).WithOperation(operation).WithSecurityScheme(securityScheme).WithBooleanStatus(!cookie.Expires.IsZero()))
	}

	return r, nil
}
