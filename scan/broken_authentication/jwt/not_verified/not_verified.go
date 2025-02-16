package notverified

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NotVerifiedJwtScanID   = "jwt.not_verified"
	NotVerifiedJwtScanName = "JWT Not Verified"
)

var issue = report.Issue{
	ID:   "broken_authentication.not_verified",
	Name: "JWT Token is not verified",

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

func ShouldBeScanned(securityScheme *auth.SecurityScheme) bool {
	return securityScheme != nil && securityScheme.GetType() != auth.None && securityScheme.GetTokenFormat() != nil && *securityScheme.GetTokenFormat() == auth.JWTTokenFormat
}

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(NotVerifiedJwtScanID, NotVerifiedJwtScanName, op)
	r.AddIssueReport(vulnReport)

	if !ShouldBeScanned(securityScheme) {
		vulnReport.Skip()
		return r.End(), nil
	}

	var token string
	if securityScheme.HasValidValue() {
		token = securityScheme.GetToken()
	} else {
		token = jwt.FakeJWT
	}

	valueWriter, err := jwt.NewJWTWriter(token)
	if err != nil {
		return r.End(), err
	}

	newToken, err := valueWriter.SignWithMethodAndRandomKey(valueWriter.GetToken().Method)
	if err != nil {
		return r.End(), err
	}

	if err = securityScheme.SetAttackValue(securityScheme.GetValidValue()); err != nil {
		return r.End(), err
	}
	attemptOne, err := scan.ScanURL(op, securityScheme)
	if err != nil {
		return r.End(), err
	}
	vulnReport.AddScanAttempt(attemptOne)
	r.AddScanAttempt(attemptOne)

	if !scan.IsUnauthorizedStatusCodeOrSimilar(attemptOne.Response) {
		vulnReport.Skip()
		return r.End(), nil
	}

	if err = securityScheme.SetAttackValue(newToken); err != nil {
		return r.End(), err
	}
	attemptTwo, err := scan.ScanURL(op, securityScheme)
	if err != nil {
		return r.End(), err
	}
	vulnReport.AddScanAttempt(attemptTwo)
	r.AddScanAttempt(attemptTwo)

	attemptTwo.WithBooleanStatus(attemptOne.Response.GetStatusCode() == attemptTwo.Response.GetStatusCode())
	vulnReport.WithBooleanStatus(attemptTwo.HasPassed())

	return r.End(), nil
}
