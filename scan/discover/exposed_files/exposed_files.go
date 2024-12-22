package exposedfiles

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
)

const (
	DiscoverableFilesScanID   = "discover.exposed_files"
	DiscoverableFilesScanName = "Discoverable exposed files"
)

type DiscoverableFilesData = discover.DiscoverData

var issue = report.Issue{
	ID:   "discover.exposed_files",
	Name: "Discoverable exposed files",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SSRF,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var discoverableFilesSeclistUrl = "https://raw.githubusercontent.com/cerberauth/vulnapi/main/seclist/lists/exposed-paths.txt"

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverableFilesScanID, DiscoverableFilesScanName, op)
	return discover.DownloadAndScanURLs("Exposed Files", discoverableFilesSeclistUrl, r, vulnReport, op, securityScheme)
}
