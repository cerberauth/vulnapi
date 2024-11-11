package acceptunauthenticated

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NoAuthOperationScanID   = "discover.accept_unauthenticated"
	NoAuthOperationScanName = "Accept Unauthenticated Operation"
)

var issue = report.Issue{
	ID:   "discover.accept_unauthenticated_operation",
	Name: "Operation May Accepts Unauthenticated Requests",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(NoAuthOperationScanID, NoAuthOperationScanName, op)

	r.AddIssueReport(vulnReport.WithBooleanStatus(securityScheme.GetType() != auth.None)).End()

	r.End()
	return r, nil
}
