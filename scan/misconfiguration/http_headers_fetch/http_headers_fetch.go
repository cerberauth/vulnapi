package httpheadersfetch

import (
	"context"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

const (
	CSPHTTPHeader                 = "Content-Security-Policy"
	HSTSHTTPHeader                = "Strict-Transport-Security"
	CORSOriginHTTPHeader          = "Access-Control-Allow-Origin"
	XContentTypeOptionsHTTPHeader = "X-Content-Type-Options"
	XFrameOptionsHTTPHeader       = "X-Frame-Options"
)

const (
	HTTPHeadersFetchScanID   = "misconfiguration.http_headers_fetch"
	HTTPHeadersFetchScanName = "HTTP Headers Fetch"
)

// FetchResult carries the single shared HTTP response that every
// http_headers_* check inspects, so the request is only made once per
// resource instead of once per header check.
type FetchResult struct {
	Attempt *finding.Attempt
}

// Check performs the single shared HTTP request the sibling http_headers_*
// checks inspect. It does not report a vulnerability itself: it only exists
// to make the request once and expose the response via ResultStore.
var Check = hxcheckdef.NewResourceCheck(
	hxcheckdef.CheckDef{ID: HTTPHeadersFetchScanID, Name: HTTPHeadersFetchScanName},
	func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
		op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
		if !ok {
			return harnessx.Result{Err: errors.New("http_headers_fetch: resource missing *operation.Operation")}, nil
		}
		securityScheme := op.GetSecurityScheme()

		attempt, err := finding.Fetch(ctx, op, securityScheme)
		if err != nil {
			return harnessx.Result{}, err
		}

		return harnessx.Result{Data: &FetchResult{Attempt: attempt}}, nil
	},
)
