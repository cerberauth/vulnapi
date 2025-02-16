package discoverableopenapi

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
)

const (
	DiscoverableOpenAPIScanID   = "discover.discoverable_openapi"
	DiscoverableOpenAPIScanName = "Discoverable OpenAPI"
)

type DiscoverableOpenAPIData = discover.DiscoverData

var issue = report.Issue{
	ID:   "discover.discoverable_openapi",
	Name: "Discoverable OpenAPI Path",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SSRF,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var openapiSeclistUrl = "https://raw.githubusercontent.com/cerberauth/vulnapi/main/seclist/lists/swagger.txt"

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverableOpenAPIScanID, DiscoverableOpenAPIScanName, op)
	r.AddIssueReport(vulnReport)
	return discover.DownloadAndScanURLs("OpenAPI", openapiSeclistUrl, r, vulnReport, op, securityScheme)
}
