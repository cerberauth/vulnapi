package httpcookiesnotsecure

import (
	"context"
	_ "embed"
	"errors"
	"net/http"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/checkutil"
	httpcookiesfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_cookies_not_secure", checkYAML)

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	_, ok := checkutil.Operation(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_cookies_not_secure: resource missing *operation.Operation")}, nil
	}

	data, ok := checkutil.Dependency[*httpcookiesfetch.FetchResult](store, httpcookiesfetch.Check.ID, resource.ID)
	if !ok || data.Attempt == nil {
		return harnessx.Result{Err: errors.New("http_cookies_not_secure: missing fetch result from dependency")}, nil
	}

	f, skip := httpcookiesfetch.EvalCookies(data.Attempt, func(c *http.Cookie) bool { return c.Secure })
	if skip {
		return harnessx.Result{Skipped: true, SkipReason: "no cookies to inspect"}, nil
	}
	if f != nil {
		return harnessx.Result{Data: f}, nil
	}
	return harnessx.Result{}, nil
})
