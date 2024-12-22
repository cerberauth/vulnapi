package wellknown

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
)

const (
	DiscoverableWellKnownScanID   = "discover.well-known"
	DiscoverableWellKnownScanName = "Discoverable well-known path"
)

type DiscoverableGraphQLPathData = discover.DiscoverData

var issue = report.Issue{
	ID:   "discover.discoverable_well_known",
	Name: "Discoverable well-known path",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SSRF,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var wellKnownSeclistUrl = "https://raw.githubusercontent.com/cerberauth/vulnapi/main/seclist/lists/well-known.txt"

func ScanHandler(op *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewIssueReport(issue).WithOperation(op).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverableWellKnownScanID, DiscoverableWellKnownScanName, op)
	return discover.DownloadAndScanURLs("Well-Known", wellKnownSeclistUrl, r, vulnReport, op, securityScheme)
}
