package algnone

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
)

var issue = report.Issue{
	ID:   "broken_authentication.alg_none",
	Name: "JWT Algorithm None is accepted",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-alg-none/?utm_source=vulnapi",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_BrokenAuthentication,
		CWE:   report.CWE_345_Insufficient_Verification_Authenticity,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
		Score:   9.3,
	},
}

func ShouldBeScanned(securitySheme auth.SecurityScheme) bool {
	if securitySheme == nil {
		return false
	}

	if _, ok := securitySheme.(*auth.JWTBearerSecurityScheme); !ok {
		return false
	}

	return true
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(AlgNoneJwtScanID, AlgNoneJwtScanName, operation)

	if !ShouldBeScanned(securityScheme) {
		vulnReport.Skip()
		r.AddVulnerabilityReport(vulnReport).End()
		return r, nil
	}

	var valueWriter *jwt.JWTWriter
	if securityScheme.HasValidValue() {
		valueWriter = securityScheme.GetValidValueWriter().(*jwt.JWTWriter)
		if valueWriter.Token.Method.Alg() == jwtlib.SigningMethodNone.Alg() {
			return nil, nil
		}
	} else {
		valueWriter, _ = jwt.NewJWTWriter(jwt.FakeJWT)
	}

	newToken, err := valueWriter.WithAlgNone()
	if err != nil {
		return r, err
	}
	securityScheme.SetAttackValue(newToken)
	vsa, err := scan.ScanURL(operation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(vsa).End()
	vulnReport.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(vsa.Response))
	r.AddVulnerabilityReport(vulnReport)

	return r, nil
}
