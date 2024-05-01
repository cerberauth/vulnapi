package discover

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverableOpenAPIScanID   = "discover.discoverable-openapi"
	DiscoverableOpenAPIScanName = "Discoverable OpenAPI"

	DiscoverableOpenAPISeverityLevel     = 0
	DiscoverableOpenAPIVulnerabilityID   = "discover.discoverable-openapi"
	DiscoverableOpenAPIVulnerabilityName = "Discoverable OpenAPI"
	DiscoverableOpenAPIVulnerabilityURL  = ""
)

var potentialOpenAPIPaths = []string{
	"/openapi",
	"/swagger.json",
	"/swagger.yaml",
	"/openapi.json",
	"/openapi.yaml",
	"/api-docs",
	"/api-docs.json",
	"/api-docs.yaml",
	"/api-docs.yml",
	"/v1/api-docs",
	"/v2/api-docs",
	"/v3/api-docs",
}
var openapiSeclistUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt"

func DiscoverableOpenAPIScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(DiscoverableOpenAPIScanID, DiscoverableOpenAPIScanName)
	handler := CreateURLScanHandler("OpenAPI", openapiSeclistUrl, potentialOpenAPIPaths, r, &report.VulnerabilityReport{
		SeverityLevel: DiscoverableOpenAPISeverityLevel,

		ID:   DiscoverableOpenAPIVulnerabilityID,
		Name: DiscoverableOpenAPIVulnerabilityName,
		URL:  DiscoverableOpenAPIVulnerabilityURL,
	})

	return handler(operation, securityScheme)
}
