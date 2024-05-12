package scenario

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	serversignature "github.com/cerberauth/vulnapi/scan/discover/server_signature"
)

func NewDiscoverScan(method string, url string, client *request.Client, reporter *report.Reporter) (*scan.Scan, error) {
	if client == nil {
		client = request.DefaultClient
	}

	operation, err := request.NewOperation(client, method, url, nil, nil, []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()})
	if err != nil {
		return nil, err
	}
	operations := request.Operations{operation}

	urlScan, err := scan.NewScan(operations, reporter)
	if err != nil {
		return nil, err
	}

	urlScan.AddScanHandler(discoverableopenapi.ScanHandler).AddScanHandler(discoverablegraphql.ScanHandler).AddScanHandler(serversignature.ScanHandler)

	return urlScan, nil
}
