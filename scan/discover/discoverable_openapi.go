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

func DiscoverableOpenAPIScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(DiscoverableOpenAPIScanID, DiscoverableOpenAPIScanName)

	return ScanURLs(potentialOpenAPIPaths, operation, securityScheme, r, &report.VulnerabilityReport{
		SeverityLevel: DiscoverableOpenAPISeverityLevel,

		OWASP2023Category: DiscoverableOpenAPIOWASP2023Category,

		ID:   DiscoverableOpenAPIVulnerabilityID,
		Name: DiscoverableOpenAPIVulnerabilityName,
		URL:  DiscoverableOpenAPIVulnerabilityURL,

		Operation: operation,
	})
}
