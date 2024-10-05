package scenario

import (
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
)

func NewDiscoverAPIScan(method string, url string, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if client == nil {
		client = request.DefaultClient
	}

	url = addDefaultProtocolWhenMissing(url)
	operation, err := request.NewOperation(method, url, nil, client)
	if err != nil {
		return nil, err
	}

	if err := operation.IsReachable(); err != nil {
		return nil, err
	}

	operations := request.Operations{operation}
	urlScan, err := scan.NewScan(operations, opts)
	if err != nil {
		return nil, err
	}

	urlScan.AddScanHandler(scan.NewOperationScanHandler(fingerprint.DiscoverFingerPrintScanID, fingerprint.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(discoverableopenapi.DiscoverableOpenAPIScanID, discoverableopenapi.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(discoverablegraphql.DiscoverableGraphQLPathScanID, discoverablegraphql.ScanHandler))

	return urlScan, nil
}
