package notverified

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
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

func ShouldBeScanned(securitySheme auth.SecurityScheme) bool {
	if securitySheme == nil {
		return false
	}

	if _, ok := securitySheme.(*auth.JWTBearerSecurityScheme); !ok {
		return false
	}

	if !securitySheme.HasValidValue() {
		return false
	}

	return true
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(NotVerifiedJwtScanID, NotVerifiedJwtScanName, operation)

	if !ShouldBeScanned(securityScheme) {
		r.AddIssueReport(vulnReport.Skip()).End()
		return r, nil
	}

	valueWriter := securityScheme.GetValidValueWriter().(*jwt.JWTWriter)

	newToken, err := valueWriter.SignWithMethodAndRandomKey(valueWriter.Token.Method)
	if err != nil {
		return r, err
	}

	securityScheme.SetAttackValue(securityScheme.GetValidValue())
	attemptOne, err := scan.ScanURL(operation, &securityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(attemptOne).End()

	if !scan.IsUnauthorizedStatusCodeOrSimilar(attemptOne.Response) {
		r.AddIssueReport(vulnReport.Skip())
		return r, nil
	}

	securityScheme.SetAttackValue(newToken)
	attemptTwo, err := scan.ScanURL(operation, &securityScheme)
	if err != nil {
		return r, err
	}

	r.AddScanAttempt(attemptTwo).End()
	vulnReport.WithBooleanStatus(attemptOne.Response.StatusCode == attemptTwo.Response.StatusCode)
	r.AddIssueReport(vulnReport)

	return r, nil
}
