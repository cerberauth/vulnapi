package scenario

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	introspectionenabled "github.com/cerberauth/vulnapi/scan/graphql/introspection_enabled"
)

func NewGraphQLScan(url string, client *request.Client, reporter *report.Reporter) (*scan.Scan, error) {
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

	url = addDefaultProtocolWhenMissing(url)
	operation, err := request.NewOperation(http.MethodPost, url, nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	if err != nil {
		return nil, err
	}

	if err := operation.IsReachable(); err != nil {
		return nil, err
	}

	operations := request.Operations{operation}
	graphqlScan, err := scan.NewScan(operations, reporter)
	if err != nil {
		return nil, err
	}

	graphqlScan.AddScanHandler(introspectionenabled.ScanHandler)
	WithAllCommonScans(graphqlScan)

	return graphqlScan, nil
}
