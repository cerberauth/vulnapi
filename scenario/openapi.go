package scenario

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
)

func NewOpenAPIScan(openapi *openapi.OpenAPI, securitySchemesValues *auth.SecuritySchemeValues, client *request.Client, reporter *report.Reporter) (*scan.Scan, error) {
	securitySchemes, err := openapi.SecuritySchemeMap(securitySchemesValues)
	if err != nil {
		return nil, err
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

	openapiScan, err := scan.NewScan(operations, reporter)
	if err != nil {
		return nil, err
	}

	WithAllCommonScans(openapiScan)

	return openapiScan, nil
}
