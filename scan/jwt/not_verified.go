package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NotVerifiedJwtScanID   = "jwt.not-verified"
	NotVerifiedJwtScanName = "JWT Not Verified"

	NotVerifiedVulnerabilitySeverityLevel = 9
	NotVerifiedVulnerabilityID            = "jwt.not-verified"
	NotVerifiedVulnerabilityName          = "JWT Not Verified"
	NotVerifiedVulnerabilityURL           = ""
)

func NotVerifiedScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(NotVerifiedJwtScanID, NotVerifiedJwtScanName)
	if !ShouldBeScanned(ss) {
		return r, nil
	}

	valueWriter := ss.GetValidValueWriter().(*jwt.JWTWriter)
	newToken, err := valueWriter.SignWithMethodAndRandomKey(valueWriter.Token.Method)
	if err != nil {
		return r, err
	}

	ss.SetAttackValue(ss.GetValidValue())
	attemptOne, err := scan.ScanURL(operation, &ss)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attemptOne).End()

	if scan.DetectNotExpectedResponse(attemptOne.Response) == nil {
		return r, nil
	}

	ss.SetAttackValue(newToken)
	attemptTwo, err := scan.ScanURL(operation, &ss)
	if err != nil {
		return r, err
	}

	r.AddScanAttempt(attemptTwo).End()

	if attemptOne.Response.StatusCode == attemptTwo.Response.StatusCode {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NotVerifiedVulnerabilitySeverityLevel,

			ID:   NotVerifiedVulnerabilityID,
			Name: NotVerifiedVulnerabilityName,
			URL:  NotVerifiedVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
