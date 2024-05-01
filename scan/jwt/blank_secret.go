package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	BlankSecretVulnerabilityScanID   = "jwt.blank_secret"
	BlankSecretVulnerabilityScanName = "JWT Blank Secret"

	BlankSecretVulnerabilitySeverityLevel     = 9
	BlankSecretVulnerabilityOWASP2023Category = report.OWASP2023BrokenAuthCategory

	BlankSecretVulnerabilityID   = "broken_authentication.jwt_blank_secret"
	BlankSecretVulnerabilityName = "JWT Blank Secret"
	BlankSecretVulnerabilityURL  = "https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-blank-secret/?utm_source=vulnapi"
)

func BlankSecretScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(BlankSecretVulnerabilityScanID, BlankSecretVulnerabilityScanName)
	if !ShouldBeScanned(ss) {
		r.End()
		return r, nil
	}

	valueWriter := ss.GetValidValueWriter().(*jwt.JWTWriter)
	newToken, err := valueWriter.SignWithKey([]byte(""))
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa, err := scan.ScanURL(operation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: BlankSecretVulnerabilitySeverityLevel,

			OWASP2023Category: BlankSecretVulnerabilityOWASP2023Category,

			ID:   BlankSecretVulnerabilityID,
			Name: BlankSecretVulnerabilityName,
			URL:  BlankSecretVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
