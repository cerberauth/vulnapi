package discover

import (
	"net/http"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverableOpenAPISeverityLevel            = 1
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
	".well-known/openapi.json",
	".well-known/openapi.yaml",
}

func DiscoverableOpenAPIScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	securityScheme.SetAttackValue(securityScheme.GetValidValue())

	base := ExtractBaseURL(operation.Request.URL)
	for _, path := range potentialOpenAPIPaths {
		newRequest, _ := http.NewRequest(http.MethodGet, base.ResolveReference(&url.URL{Path: path}).String(), nil)
		newOperation := request.NewOperationFromRequest(newRequest, []auth.SecurityScheme{securityScheme})

		attempt, err := scan.ScanURL(newOperation, &securityScheme)
		r.AddScanAttempt(attempt).End()
		if err != nil {
			return r, err
		}

		if attempt.Response.StatusCode < 300 {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: DiscoverableOpenAPISeverityLevel,
				Name:          DiscoverableOpenAPIVulnerabilityName,
				Description:   DiscoverableOpenAPIVulnerabilityDescription,
				Operation:     newOperation,
			})

			return r, nil
		}
	}

	return r, nil
}
