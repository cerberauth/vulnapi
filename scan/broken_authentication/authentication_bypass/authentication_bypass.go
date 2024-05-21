package authenticationbypass

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	AcceptsUnauthenticatedOperationScanID   = "generic.accept_unauthenticated_operation"
	AcceptsUnauthenticatedOperationScanName = "Accept Unauthenticated Operation"
)

var issue = report.Issue{
	ID:   "broken_authentication.authentication_bypass",
	Name: "Authentication is expected but can be bypassed",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_BrokenAuthentication,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
		Score:   9.3,
	},
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)

	r := report.NewScanReport(AcceptsUnauthenticatedOperationScanID, AcceptsUnauthenticatedOperationScanName, operation)
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		return r.AddVulnerabilityReport(vulnReport.Skip()).End(), nil
	}

	noAuthSecurityScheme := auth.SecurityScheme(auth.NewNoAuthSecurityScheme())
	vsa, err := scan.ScanURL(operation, &noAuthSecurityScheme)
	if err != nil {
		return r, err
	}
	vulnReport.WithBooleanStatus(scan.IsUnauthorizedStatusCodeOrSimilar(vsa.Response))
	r.AddVulnerabilityReport(vulnReport).AddScanAttempt(vsa).End()

	return r, nil
}
