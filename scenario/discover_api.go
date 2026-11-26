package scenario

import (
	"errors"
	"net/url"

	"github.com/cerberauth/harnessx"
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

func NewDiscoverAPIScan(engine *harnessx.Engine, method string, u *url.URL, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if u == nil {
		return nil, errors.New("url is required")
	}

	if client == nil {
		client = request.GetDefaultClient()
	}

	u, err := normalizeURL(u)
	if err != nil {
		return nil, err
	}
	op, err := operation.NewOperation(method, u.String(), nil, client)
	if err != nil {
		return nil, err
	}

	if err := op.IsReachable(); err != nil {
		return nil, err
	}

	operations := operation.Operations{op}
	urlScan, err := scan.NewScan(engine, operations, opts)
	if err != nil {
		return nil, err
	}

	return WithDiscoverScans(urlScan), nil
}

// WithDiscoverScans registers the API discovery checks with s.
func WithDiscoverScans(s *scan.Scan) *scan.Scan {
	s.AddCheck(fingerprint.Check, &fingerprint.Def)
	s.AddCheck(discoverableopenapi.Check, &discoverableopenapi.Def)
	s.AddCheck(discoverablegraphql.Check, &discoverablegraphql.Def)
	s.AddCheck(exposedfiles.Check, &exposedfiles.Def)
	s.AddCheck(wellknown.Check, &wellknown.Def)
	s.AddCheck(healthcheck.Check, &healthcheck.Def)

	return s
}
