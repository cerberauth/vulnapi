package httpcookies_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpcookies "github.com/cerberauth/vulnapi/scan/misconfiguration/http_cookies"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPCookiesScanHandler_Skipped_WhenNoCookies(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := httpcookies.ScanHandler(op, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.False(t, report.HasFailedIssueReport())
	assert.True(t, report.GetIssueReports()[0].HasBeenSkipped())
}

func TestHTTPCookiesScanHandler_Passed_WhenNoUnsecurePractices(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
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
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := httpcookies.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.False(t, report.HasFailedIssueReport())
}

func TestHTTPCookiesScanHandler_Failed_WhenNotHttpOnly(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
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
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := httpcookies.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPCookiesScanHandlerFailed_WhenNotSecure(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
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
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := httpcookies.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPCookiesScanHandler_Failed_WhenSameSiteNone(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
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
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := httpcookies.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPCookiesScanHandler_Failed_WhithoutSameSite(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	resp := httpmock.NewStringResponse(http.StatusOK, "OK")
	cookie := &http.Cookie{
		Name:     "cookie_name",
		Value:    "cookie_value",
		Path:     "/",
		Domain:   "localhost",
		Secure:   true,
		HttpOnly: true,
		Expires:  time.Now().Add(24 * time.Hour),
	}
	resp.Header.Add("Set-Cookie", cookie.String())
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := httpcookies.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPCookiesScanHandler_Failed_WhenExpiresNotSet(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
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
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromResponse(resp))

	report, err := httpcookies.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 5, len(report.GetIssueReports()))
	assert.True(t, report.HasFailedIssueReport())
}
