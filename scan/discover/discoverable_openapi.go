package discover

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverableOpenAPIScanID   = "discover.discoverable_openapi"
	DiscoverableOpenAPIScanName = "Discoverable OpenAPI"

	DiscoverableOpenAPISeverityLevel     = 0
	DiscoverableOpenAPIOWASP2023Category = report.OWASP2023SSRFCategory
	DiscoverableOpenAPIVulnerabilityID   = "ssrf.discoverable_openapi"
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

		OWASP2023Category: DiscoverableOpenAPIOWASP2023Category,

		ID:   DiscoverableOpenAPIVulnerabilityID,
		Name: DiscoverableOpenAPIVulnerabilityName,
		URL:  DiscoverableOpenAPIVulnerabilityURL,

		Operation: operation,
	})

	return handler(operation, securityScheme)
}
