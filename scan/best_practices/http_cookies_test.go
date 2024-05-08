package bestpractices_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPCookiesScanHandlerWhenNoCookies(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := bestpractices.HTTPCookiesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPCookiesScanHandlerWhenNoUnsecrurePractices(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
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
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := bestpractices.HTTPCookiesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPCookiesScanHandlerWhenNotHttpOnly(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	resp := httpmock.NewStringResponse(http.StatusOK, "OK")
	cookie := &http.Cookie{
		Name:     "cookie_name",
		Value:    "cookie_value",
		Path:     "/",
		Domain:   "localhost",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: false,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	resp.Header.Add("Set-Cookie", cookie.String())
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := bestpractices.HTTPCookiesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPCookiesScanHandlerWhenNotSecure(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
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
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := bestpractices.HTTPCookiesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPCookiesScanHandlerWhenSameSiteNone(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	resp := httpmock.NewStringResponse(http.StatusOK, "OK")
	cookie := &http.Cookie{
		Name:     "cookie_name",
		Value:    "cookie_value",
		Path:     "/",
		Domain:   "localhost",
		SameSite: http.SameSiteNoneMode,
		Secure:   true,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	resp.Header.Add("Set-Cookie", cookie.String())
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := bestpractices.HTTPCookiesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPCookiesScanHandlerWhenExpiresNotSet(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	resp := httpmock.NewStringResponse(http.StatusOK, "OK")
	cookie := &http.Cookie{
		Name:     "cookie_name",
		Value:    "cookie_value",
		Path:     "/",
		Domain:   "localhost",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
		Expires:  time.Time{},
	}
	resp.Header.Add("Set-Cookie", cookie.String())
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := bestpractices.HTTPCookiesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}
