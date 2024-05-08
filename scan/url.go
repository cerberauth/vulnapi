package scan

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

func NewURLScan(method string, url string, client *request.Client, reporter *report.Reporter) (*Scan, error) {
	if client == nil {
		client = request.DefaultClient
	}

	var securitySchemes []auth.SecurityScheme
	securityScheme, err := detectSecurityScheme(client.Header)
	if err != nil {
		return nil, err
	}

	if securityScheme != nil {
		securitySchemes = append(securitySchemes, securityScheme)
	} else {
		securitySchemes = append(securitySchemes, auth.NewNoAuthSecurityScheme())
	}

	operation, err := request.NewOperation(client, method, url, nil, nil, securitySchemes)
	if err != nil {
		return nil, err
	}
	operations := request.Operations{operation}

	return NewScan(operations, reporter)
}
