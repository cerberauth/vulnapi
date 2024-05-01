package bestpractices

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPCookiesScanID   = "bestpractices.http-cookies"
	HTTPCookiesScanName = "HTTP Cookies Best Practices"

	HTTPCookiesNotHTTPOnlySeverityLevel     = 0
	HTTPCookiesNotHTTPOnlyVulnerabilityID   = "bestpractices.http-cookies-not-http-only"
	HTTPCookiesNotHTTPOnlyVulnerabilityName = "Cookies not HTTP-Only"
	HTTPCookiesNotHTTPOnlyVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"

	HTTPCookiesNotSecureSeverityLevel     = 0
	HTTPCookiesNotSecureVulnerabilityID   = "bestpractices.http-cookies-not-secure"
	HTTPCookiesNotSecureVulnerabilityName = "Cookies not Secure"
	HTTPCookiesNotSecureVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#security"

	HTTPCookiesSameSiteSeverityLevel     = 0
	HTTPCookiesSameSiteVulnerabilityID   = "bestpractices.http-cookies-same-site"
	HTTPCookiesSameSiteVulnerabilityName = "Cookies SameSite not set or set to None"
	HTTPCookiesSameSiteVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value"

	HTTPCookiesExpiresSeverityLevel     = 0
	HTTPCookiesExpiresVulnerabilityID   = "bestpractices.http-cookies-expires"
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

				ID:   HTTPCookiesNotSecureVulnerabilityID,
				Name: HTTPCookiesNotSecureVulnerabilityName,
				URL:  HTTPCookiesNotSecureVulnerabilityURL,

				Operation: operation,
			})
		}

		if !cookie.HttpOnly {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesNotHTTPOnlySeverityLevel,

				ID:   HTTPCookiesNotHTTPOnlyVulnerabilityID,
				Name: HTTPCookiesNotHTTPOnlyVulnerabilityName,
				URL:  HTTPCookiesNotHTTPOnlyVulnerabilityURL,

				Operation: operation,
			})
		}

		if cookie.SameSite == http.SameSiteNoneMode {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesSameSiteSeverityLevel,

				ID:   HTTPCookiesSameSiteVulnerabilityID,
				Name: HTTPCookiesSameSiteVulnerabilityName,
				URL:  HTTPCookiesSameSiteVulnerabilityURL,

				Operation: operation,
			})
		}

		if cookie.Expires.IsZero() {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesExpiresSeverityLevel,

				ID:   HTTPCookiesExpiresVulnerabilityID,
				Name: HTTPCookiesExpiresVulnerabilityName,
				URL:  HTTPCookiesExpiresVulnerabilityURL,

				Operation: operation,
			})
		}
	}

	return r, nil
}
