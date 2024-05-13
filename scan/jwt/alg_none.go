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
	AlgNoneJwtScanID   = "jwt.alg_none"
	AlgNoneJwtScanName = "JWT None Algorithm"

	AlgNoneVulnerabilitySeverityLevel     = 9
	AlgNoneVulnerabilityOWASP2023Category = report.OWASP2023BrokenAuthCategory

	AlgNoneVulnerabilityID   = "broken_authentication.jwt_alg_none"
	AlgNoneVulnerabilityName = "JWT None Algorithm"
	AlgNoneVulnerabilityURL  = "https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-alg-none/?utm_source=vulnapi"
)

func AlgNoneJwtScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	if !ShouldBeScanned(ss) {
		return nil, nil
	}

	var valueWriter *jwt.JWTWriter
	if ss.HasValidValue() {
		valueWriter = ss.GetValidValueWriter().(*jwt.JWTWriter)
		if valueWriter.Token.Method.Alg() == jwtlib.SigningMethodNone.Alg() {
			return nil, nil
		}
	} else {
		valueWriter, _ = jwt.NewJWTWriter(jwt.FakeJWT)
	}

	r := report.NewScanReport(AlgNoneJwtScanID, AlgNoneJwtScanName, operation)
	newToken, err := valueWriter.WithAlgNone()
	if err != nil {
		return r, err
	}
	ss.SetAttackValue(newToken)
	vsa, err := scan.ScanURL(operation, &ss)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(vsa).End()

	if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: AlgNoneVulnerabilitySeverityLevel,

			OWASP2023Category: AlgNoneVulnerabilityOWASP2023Category,

			ID:   AlgNoneVulnerabilityID,
			Name: AlgNoneVulnerabilityName,
			URL:  AlgNoneVulnerabilityURL,
		})
	}

	return r, nil
}
