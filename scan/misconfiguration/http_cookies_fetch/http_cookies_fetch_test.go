package httpcookiesfetch_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpcookiesfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies_fetch"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPCookiesFetch_FetchesOnce(t *testing.T) {
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

	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	result, err := httpcookiesfetch.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())

	data, ok := harnessx.DataAs[*httpcookiesfetch.FetchResult](result)
	require.True(t, ok)
	require.NotNil(t, data.Attempt)
	assert.Equal(t, 1, len(data.Attempt.Response.GetCookies()))
}
