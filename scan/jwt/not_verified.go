package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	jwtlib "github.com/golang-jwt/jwt/v5"
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
	newTokenA, err := valueWriter.SignWithMethodAndKey(jwtlib.SigningMethodHS256, []byte("a"))
	if err != nil {
		return r, err
	}

	newTokenB, err := valueWriter.SignWithMethodAndKey(jwtlib.SigningMethodHS256, []byte("b"))
	if err != nil {
		return r, err
	}

	ss.SetAttackValue(newTokenA)
	vsa1, err := scan.ScanURL(operation, &ss)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(vsa1)

	ss.SetAttackValue(newTokenB)
	vsa2, err := scan.ScanURL(operation, &ss)
	if err != nil {
		return r, err
	}

	r.AddScanAttempt(vsa2)
	r.End()

	if vsa1.Response.StatusCode != vsa2.Response.StatusCode {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NotVerifiedVulnerabilitySeverityLevel,
			Name:          NotVerifiedVulnerabilityName,
			Description:   NotVerifiedVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
