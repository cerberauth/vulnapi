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

	HTTPCookiesNotHTTPOnlySeverityLevel            = 0
	HTTPCookiesNotHTTPOnlyVulnerabilityName        = "Cookies not HTTP-Only"
	HTTPCookiesNotHTTPOnlyVulnerabilityDescription = "Cookies should be http-only."

	HTTPCookiesNotSecureSeverityLevel            = 0
	HTTPCookiesNotSecureVulnerabilityName        = "Cookies not Secure"
	HTTPCookiesNotSecureVulnerabilityDescription = "Cookies should be secure."

	HTTPCookiesSameSiteSeverityLevel            = 0
	HTTPCookiesSameSiteVulnerabilityName        = "Cookies SameSite not set or set to None"
	HTTPCookiesSameSiteVulnerabilityDescription = "Cookies should have SameSite attribute set to Strict or Lax."

	HTTPCookiesExpiresSeverityLevel            = 0
	HTTPCookiesExpiresVulnerabilityName        = "Cookies Expires not set"
	HTTPCookiesExpiresVulnerabilityDescription = "Cookies should have Expires attribute set."
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
				Name:          HTTPCookiesNotSecureVulnerabilityName,
				Description:   HTTPCookiesNotSecureVulnerabilityDescription,
				Operation:     operation,
			})
		}

		if !cookie.HttpOnly {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesNotHTTPOnlySeverityLevel,
				Name:          HTTPCookiesNotHTTPOnlyVulnerabilityName,
				Description:   HTTPCookiesNotHTTPOnlyVulnerabilityDescription,
				Operation:     operation,
			})
		}

		if cookie.SameSite == http.SameSiteNoneMode {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesSameSiteSeverityLevel,
				Name:          HTTPCookiesSameSiteVulnerabilityName,
				Description:   HTTPCookiesSameSiteVulnerabilityDescription,
				Operation:     operation,
			})
		}

		if cookie.Expires.IsZero() {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: HTTPCookiesExpiresSeverityLevel,
				Name:          HTTPCookiesExpiresVulnerabilityName,
				Description:   HTTPCookiesExpiresVulnerabilityDescription,
				Operation:     operation,
			})
		}
	}

	return r, nil
}
