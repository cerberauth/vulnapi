package scenario

import (
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	exposedfiles "github.com/cerberauth/vulnapi/scan/discover/exposed_files"
	"github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	"github.com/cerberauth/vulnapi/scan/discover/healthcheck"
	wellknown "github.com/cerberauth/vulnapi/scan/discover/well-known"
)

func NewDiscoverAPIScan(method string, url string, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if client == nil {
		client = request.GetDefaultClient()
	}

	url = addDefaultProtocolWhenMissing(url)
	op, err := operation.NewOperation(method, url, nil, client)
	if err != nil {
		return nil, err
	}

	if err := op.IsReachable(); err != nil {
		return nil, err
	}

	operations := operation.Operations{op}
	urlScan, err := scan.NewScan(operations, opts)
	if err != nil {
		return nil, err
	}

	urlScan.AddScanHandler(scan.NewOperationScanHandler(fingerprint.DiscoverFingerPrintScanID, fingerprint.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(discoverableopenapi.DiscoverableOpenAPIScanID, discoverableopenapi.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(discoverablegraphql.DiscoverableGraphQLPathScanID, discoverablegraphql.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(exposedfiles.DiscoverableFilesScanID, exposedfiles.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(wellknown.DiscoverableWellKnownScanID, wellknown.ScanHandler))
	urlScan.AddScanHandler(scan.NewOperationScanHandler(healthcheck.DiscoverableHealthCheckScanID, healthcheck.ScanHandler))

	return urlScan, nil
}
