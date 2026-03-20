package kidinjection

import (
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	KidInjectionScanID   = "jwt.kid_injection"
	KidInjectionScanName = "JWT KID Injection"
)

type KidInjectionType string

const (
	KidInjectionTypeSQLInjection  KidInjectionType = "sql_injection"
	KidInjectionTypePathTraversal KidInjectionType = "path_traversal"
)

type KidInjectionData struct {
	Type KidInjectionType `json:"type"`
}

var issue = report.Issue{
	ID:   "broken_authentication.kid_injection",
	Name: "JWT KID Header Injection",
	URL:  "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection?utm_source=vulnapi-report",

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
	r := report.NewScanReport(KidInjectionScanID, KidInjectionScanName, op)
	r.AddIssueReport(vulnReport)

	if !ShouldBeScanned(securityScheme) {
		vulnReport.Skip()
		return r.End(), nil
	}

	tokenString := securityScheme.GetToken()

	sqlToken, err := exploit.KidSQLInjection(tokenString, exploit.DefaultKidSQLPayload, []byte("secret")) //nolint:gosec
	if err != nil {
		return r.End(), err
	}
	if err = securityScheme.SetAttackValue(sqlToken); err != nil {
		return r.End(), err
	}
	vsaSQL, err := scan.ScanURL(op, securityScheme)
	if err != nil {
		return r.End(), err
	}
	vsaSQL.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(vsaSQL.Response))
	vulnReport.AddScanAttempt(vsaSQL)
	r.AddScanAttempt(vsaSQL)

	if vsaSQL.HasFailed() {
		vulnReport.Fail()
		r.WithData(&KidInjectionData{Type: KidInjectionTypeSQLInjection})
		return r.End(), nil
	}

	pathToken, err := exploit.KidPathTraversal(tokenString, exploit.DefaultKidPathTraversalPayload, []byte("")) //nolint:gosec
	if err != nil {
		return r.End(), err
	}
	if err = securityScheme.SetAttackValue(pathToken); err != nil {
		return r.End(), err
	}
	vsaPath, err := scan.ScanURL(op, securityScheme)
	if err != nil {
		return r.End(), err
	}
	vsaPath.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(vsaPath.Response))
	vulnReport.AddScanAttempt(vsaPath)
	r.AddScanAttempt(vsaPath)

	if vsaPath.HasFailed() {
		vulnReport.Fail()
		r.WithData(&KidInjectionData{Type: KidInjectionTypePathTraversal})
		return r.End(), nil
	}

	vulnReport.Pass()
	return r.End(), nil
}
