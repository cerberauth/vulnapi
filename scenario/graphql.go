package scenario

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	introspectionenabled "github.com/cerberauth/vulnapi/scan/graphql/introspection_enabled"
)

func NewGraphQLScan(url string, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if client == nil {
		client = request.DefaultClient
	}

	securityScheme, err := detectSecurityScheme(client.Header)
	if err != nil {
		return nil, err
	}

	var securitySchemes []auth.SecurityScheme
	if securityScheme != nil {
		securitySchemes = []auth.SecurityScheme{securityScheme}
	} else {
		securitySchemes = []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	}

	url = addDefaultProtocolWhenMissing(url)
	operation, err := request.NewOperation(http.MethodPost, url, nil, client)
	if err != nil {
		return nil, err
	}
	operation.SetSecuritySchemes(securitySchemes)

	if err := operation.IsReachable(); err != nil {
		return nil, err
	}

	operations := request.Operations{operation}
	graphqlScan, err := scan.NewScan(operations, opts)
	if err != nil {
		return nil, err
	}

	WithAllCommonScans(graphqlScan)
	graphqlScan.AddScanHandler(scan.NewOperationScanHandler(introspectionenabled.GraphqlIntrospectionScanID, introspectionenabled.ScanHandler))

	return graphqlScan, nil
}
