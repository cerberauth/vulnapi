package discover

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverableOpenAPISeverityLevel            = 0
	DiscoverableOpenAPIVulnerabilityName        = "Discoverable OpenAPI"
	DiscoverableOpenAPIVulnerabilityDescription = "An OpenAPI file is exposed without protection. This can lead to information disclosure and security issues"
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
	handler := CreateURLScanHandler("OpenAPI", openapiSeclistUrl, potentialOpenAPIPaths, &report.VulnerabilityReport{
		SeverityLevel: DiscoverableOpenAPISeverityLevel,
		Name:          DiscoverableOpenAPIVulnerabilityName,
		Description:   DiscoverableOpenAPIVulnerabilityDescription,
	})

	return handler(operation, securityScheme)
}
