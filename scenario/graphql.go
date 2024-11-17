package scenario

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	introspectionenabled "github.com/cerberauth/vulnapi/scan/graphql/introspection_enabled"
)

func NewGraphQLScan(url string, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if client == nil {
		client = request.GetDefaultClient()
	}

	securityScheme, err := detectSecurityScheme(client.Header)
	if err != nil {
		return nil, err
	}

	var securitySchemes []*auth.SecurityScheme
	if securityScheme != nil {
		securitySchemes = []*auth.SecurityScheme{securityScheme}
	} else {
		securitySchemes = []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	}

	url = addDefaultProtocolWhenMissing(url)
	op, err := operation.NewOperation(http.MethodPost, url, nil, client)
	if err != nil {
		return nil, err
	}
	op.SetSecuritySchemes(securitySchemes)

	if err := op.IsReachable(); err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &scan.ScanOptions{}
	}

	if opts.Reporter == nil {
		opts.Reporter = report.NewReporterWithGraphQL(url, securitySchemes)
	}

	operations := operation.Operations{op}
	graphqlScan, err := scan.NewScan(operations, opts)
	if err != nil {
		return nil, err
	}

	WithAllCommonScans(graphqlScan)
	graphqlScan.AddScanHandler(scan.NewOperationScanHandler(introspectionenabled.GraphqlIntrospectionScanID, introspectionenabled.ScanHandler))

	return graphqlScan, nil
}
