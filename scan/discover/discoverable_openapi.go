package discover

import (
	"fmt"
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

var possibleOpenAPIPaths = []string{
	"/openapi",
	"/swagger.json",
	"/swagger.yaml",
	"/openapi.json",
	"/openapi.yaml",
	"/api-docs",
	"/api-docs.json",
	"/api-docs.yaml",
	"/api-docs.yml",
	"/v2/api-docs",
	"/v3/api-docs",
	".well-known/openapi.json",
	".well-known/openapi.yaml",
}

func extractBase(inputURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}

	baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	return base, nil
}

func DiscoverableOpenAPIScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	securityScheme.SetAttackValue(securityScheme.GetValidValue())

	base, err := extractBase(operation.Url)
	if err != nil {
		return r, err
	}

	for _, path := range possibleOpenAPIPaths {
		newOperation := operation.Clone()
		newOperation.Url = base.ResolveReference(&url.URL{Path: path}).String()

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
