package httpcookiesfetch

import (
	"context"
	"errors"
	"net/http"
	"strings"

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

// EvalCookies evaluates predicate against every cookie in the response and
// returns a finding when any cookie fails it. The finding's Parameter is the
// first failing cookie, and Extra["cookies"] lists every failing cookie.
// skip is true when there are no cookies to evaluate at all.
func EvalCookies(attempt *finding.Attempt, predicate func(*http.Cookie) bool) (f *finding.Finding, skip bool) {
	cookies := attempt.Response.GetCookies()
	if len(cookies) == 0 {
		return nil, true
	}

	var failing []string
	for _, cookie := range cookies {
		if !predicate(cookie) {
			failing = append(failing, cookie.Name)
		}
	}
	if len(failing) == 0 {
		return nil, false
	}
	return &finding.Finding{
		Parameter: failing[0],
		Attempt:   attempt,
		Extra:     map[string]string{"cookies": strings.Join(failing, ", ")},
	}, false
}
