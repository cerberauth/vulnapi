package blanksecret

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
)

const (
	BlankSecretVulnerabilityScanID   = "jwt.blank_secret"
	BlankSecretVulnerabilityScanName = "JWT Blank Secret"
)

var issue = report.Issue{
	ID:   "broken_authentication.blank_secret",
	Name: "JWT Secret used for signing is blank",
	URL:  "https://vulnapi.cerberauth.com/docs/vulnerabilities/broken-authentication/jwt-blank-secret?utm_source=vulnapi",

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
	r := report.NewScanReport(BlankSecretVulnerabilityScanID, BlankSecretVulnerabilityScanName, op)
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

	newToken, err := valueWriter.SignWithKey([]byte(""))
	if err != nil {
		return r.End(), err
	}
	if err = securityScheme.SetAttackValue(newToken); err != nil {
		return r.End(), err
	}
	vsa, err := scan.ScanURL(op, securityScheme)
	if err != nil {
		return r.End(), err
	}
	vsa.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(vsa.Response))
	vulnReport.WithBooleanStatus(vsa.HasPassed()).AddScanAttempt(vsa)
	r.AddScanAttempt(vsa)

	return r.End(), nil
}
