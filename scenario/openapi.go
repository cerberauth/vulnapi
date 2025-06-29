package scenario

import (
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
)

func NewOpenAPIScan(openapi *openapi.OpenAPI, securitySchemesValues *openapi.SecuritySchemeValues, client *request.Client, reporter *report.Reporter, opts *scan.ScanOptions) (*scan.Scan, error) {
	if client == nil {
		client = request.GetDefaultClient()
	}

	securitySchemes, err := openapi.SecuritySchemeMap(securitySchemesValues)
	if err != nil {
		return nil, err
	}
	for _, securityScheme := range securitySchemes {
		client.ClearSecurityScheme(securityScheme)
	}

	operations, err := openapi.Operations(client, securitySchemes)
	if err != nil {
		return nil, err
	}

	if len(operations) == 0 {
		return nil, nil
	}
	if err := operations[0].IsReachable(); err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &scan.ScanOptions{}
	}

	if reporter == nil {
		reporter = report.NewReporterWithOpenAPIDoc(openapi.Doc, operations)
	}

	openapiScan, err := scan.NewScan(operations, reporter, opts)
	if err != nil {
		return nil, err
	}
	WithAllCommonScans(openapiScan)

	return openapiScan, nil
}
