package scenario

import (
	"errors"
	"net/url"

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

func NewDiscoverAPIScan(method string, u *url.URL, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if u == nil {
		return nil, errors.New("url is required")
	}

	if client == nil {
		client = request.GetDefaultClient()
	}

	u = addDefaultProtocolWhenMissing(u)
	op, err := operation.NewOperation(method, u.String(), nil, client)
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
