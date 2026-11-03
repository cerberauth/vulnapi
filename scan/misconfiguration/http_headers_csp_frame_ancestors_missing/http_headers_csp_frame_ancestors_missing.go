package httpheaderscspframeancestorsmissing

import (
	"context"
	_ "embed"
	"errors"
	"strings"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/checkutil"
	"github.com/cerberauth/vulnapi/internal/finding"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_headers_csp_frame_ancestors_missing", checkYAML)

// CheckCSPFrameAncestors reports whether cspHeader restricts who can frame
// the response with a frame-ancestors directive: 'none', 'self' or explicit
// origins. A wildcard or a bare scheme (e.g. "https:") allows any site.
func CheckCSPFrameAncestors(cspHeader string) bool {
	for _, directive := range strings.Split(cspHeader, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "frame-ancestors") {
			continue
		}

		for _, source := range fields[1:] {
			if source == "*" || strings.HasSuffix(source, ":") {
				return false
			}
		}
		return true
	}

	return false
}

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	_, ok := checkutil.Operation(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_headers_csp_frame_ancestors_missing: resource missing *operation.Operation")}, nil
	}

	data, ok := checkutil.Dependency[*httpheadersfetch.FetchResult](store, httpheadersfetch.Check.ID, resource.ID)
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
