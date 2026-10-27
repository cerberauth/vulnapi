package httpheadershstsmissing

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/checkutil"
	"github.com/cerberauth/vulnapi/internal/finding"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_headers_hsts_missing", checkYAML)

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	_, ok := checkutil.Operation(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_headers_hsts_missing: resource missing *operation.Operation")}, nil
	}

	data, ok := checkutil.Dependency[*httpheadersfetch.FetchResult](store, httpheadersfetch.Check.ID, resource.ID)
	if !ok || data.Attempt == nil {
		return harnessx.Result{Err: errors.New("http_headers_hsts_missing: missing fetch result from dependency")}, nil
	}
	attempt := data.Attempt

	if attempt.Response.GetHeader().Get(httpheadersfetch.HSTSHTTPHeader) != "" {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Data: &finding.Finding{
		Parameter: httpheadersfetch.HSTSHTTPHeader,
		Attempt:   attempt,
	}}, nil
})
