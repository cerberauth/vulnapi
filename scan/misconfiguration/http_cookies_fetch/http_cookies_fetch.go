package httpcookiesfetch

import (
	"context"
	"errors"
	"net/http"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

const (
	HTTPCookiesFetchScanID   = "misconfiguration.http_cookies_fetch"
	HTTPCookiesFetchScanName = "HTTP Cookies Fetch"
)

type FetchResult struct {
	Attempt *finding.Attempt
}

var Check = hxcheckdef.NewResourceCheck(
	hxcheckdef.CheckDef{ID: HTTPCookiesFetchScanID, Name: HTTPCookiesFetchScanName},
	func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
		op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
		if !ok {
			return harnessx.Result{Err: errors.New("http_cookies_fetch: resource missing *operation.Operation")}, nil
		}
		securityScheme := op.GetSecurityScheme()

		attempt, err := finding.Fetch(ctx, op, securityScheme)
		if err != nil {
			return harnessx.Result{}, err
		}

		return harnessx.Result{Data: &FetchResult{Attempt: attempt}}, nil
	},
)

// EvalCookies evaluates predicate against every cookie in the response, in
// order - the last cookie evaluated determines the outcome, matching this
// check family's original semantics. skip is true when there are no cookies
// to evaluate at all.
func EvalCookies(attempt *finding.Attempt, predicate func(*http.Cookie) bool) (f *finding.Finding, skip bool) {
	cookies := attempt.Response.GetCookies()
	if len(cookies) == 0 {
		return nil, true
	}

	last := cookies[len(cookies)-1]
	if predicate(last) {
		return nil, false
	}
	return &finding.Finding{Parameter: last.Name, Attempt: attempt}, false
}
