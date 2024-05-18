package discoverableopenapi

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
)

const (
	DiscoverableOpenAPIScanID   = "discover.discoverable_openapi"
	DiscoverableOpenAPIScanName = "Discoverable OpenAPI"
)

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

// Partly retrieved from: https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt
var potentialOpenAPIPaths = []string{
	"/openapi",
	"/swagger.json",
	"/swagger.yaml",
	"/openapi.json",
	"/openapi.yaml",
	"/openapi.yml",
	"/swagger/v1/swagger.json",
	"/swagger-ui/swagger.json",
	"/apidocs/swagger.json",
	"/api-docs/swagger.json",
	"/api-docs.json",
	"/api-docs.yaml",
	"/api-docs.yml",
	"/v1/swagger.json",
	"/api/swagger.json",
	"/api/swagger-ui.json",
	"/api/v1/swagger-ui.json",
	"/api/v2/swagger-ui.json",
	"/.well-known/openapi.yaml",
	"/.well-known/openapi.yml",
	"/.well-known/openapi.json",
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverableOpenAPIScanID, DiscoverableOpenAPIScanName, operation)

	return discover.ScanURLs(potentialOpenAPIPaths, operation, securityScheme, r, vulnReport)
}
