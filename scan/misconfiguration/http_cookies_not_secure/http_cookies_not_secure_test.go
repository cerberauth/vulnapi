package httpcookiesnotsecure_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpcookiesfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_fetch"
	httpcookiesnotsecure "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_not_secure"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cookiesStoreFor(t *testing.T, op *operation.Operation) harnessx.ResultStore {
	t.Helper()
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	result, err := httpcookiesfetch.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
	require.NoError(t, err)
	result.CheckID = httpcookiesfetch.Check.ID
	result.ResourceID = op.ID
	return harnessx.NewStaticResultStore(result)
}

func runCheck(op *operation.Operation, store harnessx.ResultStore) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httpcookiesnotsecure.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, store)
}

func TestHTTPCookiesNotSecure_Skipped_WhenNoCookies(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	store := cookiesStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	assert.True(t, result.Skipped)
}

func TestHTTPCookiesNotSecure_Passed_WhenNoUnsecurePractices(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	resp := httpmock.NewStringResponse(http.StatusOK, "OK")
	cookie := &http.Cookie{
		Name:     "cookie_name",
		Value:    "cookie_value",
		Path:     "/",
		Domain:   "localhost",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	resp.Header.Add("Set-Cookie", cookie.String())
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.ResponderFromResponse(resp))

	store := cookiesStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestHTTPCookiesNotSecure_Failed_WhenNotSecure(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	resp := httpmock.NewStringResponse(http.StatusOK, "OK")
	cookie := &http.Cookie{
		Name:     "cookie_name",
		Value:    "cookie_value",
		Path:     "/",
		Domain:   "localhost",
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	resp.Header.Add("Set-Cookie", cookie.String())
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.ResponderFromResponse(resp))

	store := cookiesStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	assert.Equal(t, "cookie_name", f.Parameter)
}
