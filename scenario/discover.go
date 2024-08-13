package scenario

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
)

func NewDiscoverScan(method string, url string, client *request.Client, reporter *report.Reporter) (*scan.Scan, error) {
	if client == nil {
		client = request.DefaultClient
	}

	url = addDefaultProtocolWhenMissing(url)
	operation, err := request.NewOperation(client, method, url, nil, nil, []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()})
	if err != nil {
		return nil, err
	}
	operations := request.Operations{operation}

	urlScan, err := scan.NewScan(operations, reporter)
	if err != nil {
		return nil, err
	}

	urlScan.AddScanHandler(fingerprint.ScanHandler).AddScanHandler(discoverableopenapi.ScanHandler).AddScanHandler(discoverablegraphql.ScanHandler)

	return urlScan, nil
}
