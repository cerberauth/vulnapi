package httpheaderscontentoptionsmissing

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_headers_content_options_missing", checkYAML)

func operationOf(resource harnessx.Resource) (*operation.Operation, bool) {
	return harnessx.ResourceDataAs[*operation.Operation](resource)
}

// fetchResultOf fetches the http_headers_fetch check's result for this
// resource: it already made the single shared HTTP request, so this check
// reuses that response instead of making its own.
func fetchResultOf(store harnessx.ResultStore, resourceID string) (*httpheadersfetch.FetchResult, bool) {
	res, ok := store.GetForResource(httpheadersfetch.Check.ID, resourceID)
	if !ok {
		return nil, false
	}
	data, ok := harnessx.DataAs[*httpheadersfetch.FetchResult](res)
	return data, ok
}

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	_, ok := operationOf(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_headers_content_options_missing: resource missing *operation.Operation")}, nil
	}

	data, ok := fetchResultOf(store, resource.ID)
	if !ok || data.Attempt == nil {
		return harnessx.Result{Err: errors.New("http_headers_content_options_missing: missing fetch result from dependency")}, nil
	}
	attempt := data.Attempt

	if attempt.Response.GetHeader().Get(httpheadersfetch.XContentTypeOptionsHTTPHeader) != "" {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Data: &finding.Finding{
		Parameter: httpheadersfetch.XContentTypeOptionsHTTPHeader,
		Attempt:   attempt,
	}}, nil
})
