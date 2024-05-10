package scan

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/report"
)

func NewOpenAPIScan(openapi *openapi.OpenAPI, validToken *string, client *request.Client, reporter *report.Reporter) (*Scan, error) {
	securitySchemesValues := auth.NewSecuritySchemeValuesWithDefault(validToken)
	securitySchemes, err := openapi.SecuritySchemeMap(securitySchemesValues)
	if err != nil {
		return nil, err
	}

	operations, err := openapi.Operations(client, securitySchemes)
	if err != nil {
		return nil, err
	}

	return NewScan(operations, reporter)
}
