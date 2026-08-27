package httpheaderscspframeancestorsmissing

import (
	"context"
	_ "embed"
	"errors"
	"strings"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_headers_csp_frame_ancestors_missing", checkYAML)

func CheckCSPFrameAncestors(cspHeader string) bool {
	directives := strings.Split(cspHeader, ";")
	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if strings.HasPrefix(directive, "frame-ancestors") {
			if strings.Contains(directive, "none") {
				return true
			}
		}
	}

	return false
}

func operationOf(resource harnessx.Resource) (*operation.Operation, bool) {
	return harnessx.ResourceDataAs[*operation.Operation](resource)
}

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
		return harnessx.Result{Err: errors.New("http_headers_csp_frame_ancestors_missing: resource missing *operation.Operation")}, nil
	}

	data, ok := fetchResultOf(store, resource.ID)
	if !ok || data.Attempt == nil {
		return harnessx.Result{Err: errors.New("http_headers_csp_frame_ancestors_missing: missing fetch result from dependency")}, nil
	}
	attempt := data.Attempt

	cspHeader := attempt.Response.GetHeader().Get(httpheadersfetch.CSPHTTPHeader)
	if CheckCSPFrameAncestors(cspHeader) {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Data: &finding.Finding{
		Parameter: httpheadersfetch.CSPHTTPHeader,
		Attempt:   attempt,
	}}, nil
})
