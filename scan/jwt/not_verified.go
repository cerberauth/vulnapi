package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NotVerifiedVulnerabilitySeverityLevel = 9
	NotVerifiedVulnerabilityName          = "JWT Not Verified"
	NotVerifiedVulnerabilityDescription   = "JWT is not verified allowing attackers to issue valid JWT."
)

func NotVerifiedScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
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
	r.AddScanAttempt(attemptOne)

	if scan.DetectNotExpectedResponse(attemptOne.Response) == nil {
		return r, nil
	}

	ss.SetAttackValue(newToken)
	attemptTwo, err := scan.ScanURL(operation, &ss)
	if err != nil {
		return r, err
	}

	r.AddScanAttempt(attemptTwo)
	r.End()

	if attemptOne.Response.StatusCode == attemptTwo.Response.StatusCode {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NotVerifiedVulnerabilitySeverityLevel,
			Name:          NotVerifiedVulnerabilityName,
			Description:   NotVerifiedVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
