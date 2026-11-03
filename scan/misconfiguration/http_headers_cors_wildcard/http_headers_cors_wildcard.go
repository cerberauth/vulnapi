package httpheaderscorswildcard

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

var Def = hxcheckdef.MustParseCheckDefYAML("http_headers_cors_wildcard", checkYAML)

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	_, ok := checkutil.Operation(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_headers_cors_wildcard: resource missing *operation.Operation")}, nil
	}

	data, ok := checkutil.Dependency[*httpheadersfetch.FetchResult](store, httpheadersfetch.Check.ID, resource.ID)
	if !ok || data.Attempt == nil {
		return harnessx.Result{Err: errors.New("http_headers_cors_wildcard: missing fetch result from dependency")}, nil
	}
	attempt := data.Attempt

	// This decision depends on the live HTTP response (whether CORS is
	// configured at all), so it stays as an inline Skip() here rather
	// than a static Check.Skip decision.
	allowOrigin := attempt.Response.GetHeader().Get(httpheadersfetch.CORSOriginHTTPHeader)
	if allowOrigin == "" {
		return harnessx.Result{Skipped: true, SkipReason: "CORS is not configured"}, nil
	}
	if allowOrigin != "*" {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Data: &finding.Finding{
		Parameter: httpheadersfetch.CORSOriginHTTPHeader,
		Attempt:   attempt,
	}}, nil
})
