package scenario

import (
	"bytes"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
)

func NewURLScan(method string, url string, data string, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
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

	body := bytes.NewBuffer([]byte(data))

	url = addDefaultProtocolWhenMissing(url)
	operation, err := request.NewOperation(method, url, body, client)
	operation.GenerateID()
	if err != nil {
		return nil, err
	}
	operation.SetSecuritySchemes(securitySchemes)

	if err := operation.IsReachable(); err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &scan.ScanOptions{}
	}

	if opts.Reporter == nil {
		opts.Reporter = report.NewReporterWithCurl(method, url, data, client.Header, client.Cookies, securitySchemes)
	}

	operations := request.Operations{operation}
	urlScan, err := scan.NewScan(operations, opts)
	if err != nil {
		return nil, err
	}

	urlScan.AddOperationScanHandler(scan.NewOperationScanHandler(discoverableopenapi.DiscoverableOpenAPIScanID, discoverableopenapi.ScanHandler))
	urlScan.AddOperationScanHandler(scan.NewOperationScanHandler(discoverablegraphql.DiscoverableGraphQLPathScanID, discoverablegraphql.ScanHandler))
	WithAllCommonScans(urlScan)

	return urlScan, nil
}
