package httpmethodoverride_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	httpmethodoverride "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPMethodOverrideScanHandler(t *testing.T) {
	value := jwt.FakeJWT
	tests := []struct {
		name           string
		operation      *request.Operation
		securityScheme auth.SecurityScheme
	}{
		{
			name:           "MethodNotAllowed",
			operation:      request.MustNewOperation(http.MethodGet, "http://example.com", nil, nil),
			securityScheme: auth.NewNoAuthSecurityScheme(),
		},
		{
			name:           "MethodOverrideDetected",
			operation:      request.MustNewOperation(http.MethodPost, "http://example.com/test", nil, nil),
			securityScheme: auth.NewNoAuthSecurityScheme(),
		},
		{
			name:           "AuthenticationBypassDetected",
			operation:      request.MustNewOperation(http.MethodPost, "http://example.com/test", nil, nil),
			securityScheme: auth.MustNewAuthorizationJWTBearerSecurityScheme("securityScheme", &value),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := httpmethodoverride.ScanHandler(tt.operation, tt.securityScheme)
			if err != nil {
				t.Errorf("ScanHandler() error = %v", err)
				return
			}
			if got == nil {
				t.Errorf("ScanHandler() got = nil, want non-nil")
			}
		})
	}
}

func TestHTTPMethodOverrideScanHandler_When_Error(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	r, err := httpmethodoverride.ScanHandler(operation, securityScheme)

	require.Error(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(r.Issues))
	assert.False(t, r.HasFailedIssueReport())
	assert.Equal(t, r.Issues[0].Status, report.IssueReportStatusNone)
	assert.Equal(t, r.Issues[1].Status, report.IssueReportStatusNone)
}

func TestHTTPMethodOverrideScanHandler_Passed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), httpmock.NewBytesResponder(http.StatusMethodNotAllowed, nil))

	report, err := httpmethodoverride.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 12, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(report.Issues))
	assert.False(t, report.HasFailedIssueReport())
	assert.True(t, report.Issues[0].HasPassed())
	assert.True(t, report.Issues[1].HasBeenSkipped())
}

func TestHTTPMethodOverrideScanHandler_Failed_With_Header(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet {
			return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
		}
		return httpmock.NewJsonResponse(http.StatusMethodNotAllowed, nil)
	})

	report, err := httpmethodoverride.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 4, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(report.Issues))
	assert.True(t, report.HasFailedIssueReport())
	assert.True(t, report.Issues[0].HasFailed())
	assert.True(t, report.Issues[1].HasBeenSkipped())
}

func TestHTTPMethodOverrideScanHandler_Failed_With_Query_Parameter(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), httpmock.NewBytesResponder(http.StatusMethodNotAllowed, nil))

	urlWithOverrideQuery, _ := url.Parse(operation.URL.String())
	newQueryValues := urlWithOverrideQuery.Query()
	newQueryValues.Set("_method", http.MethodGet)
	urlWithOverrideQuery.RawQuery = newQueryValues.Encode()
	httpmock.RegisterResponder(http.MethodPost, urlWithOverrideQuery.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	report, err := httpmethodoverride.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 9, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(report.Issues))
	assert.True(t, report.HasFailedIssueReport())
	assert.True(t, report.Issues[0].HasFailed())
	assert.True(t, report.Issues[1].HasBeenSkipped())
}

func TestHTTPMethodOverrideScanHandler_Authentication_ByPass_Passed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := jwt.FakeJWT
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("securityScheme", &token)
	operation := request.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet && req.Header.Get("Authorization") == "Bearer "+string(token) {
			return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
		}
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet && req.Header.Get("Authorization") == "" {
			return httpmock.NewJsonResponse(http.StatusUnauthorized, nil)
		}
		return httpmock.NewJsonResponse(http.StatusMethodNotAllowed, nil)
	})

	report, err := httpmethodoverride.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 5, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(report.Issues))
	assert.True(t, report.HasFailedIssueReport())
	assert.True(t, report.Issues[0].HasFailed())
	assert.True(t, report.Issues[1].HasPassed())
}

func TestHTTPMethodOverrideScanHandler_Authentication_ByPass_Failed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := jwt.FakeJWT
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("securityScheme", &token)
	operation := request.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet {
			return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
		}
		return httpmock.NewJsonResponse(http.StatusMethodNotAllowed, nil)
	})

	report, err := httpmethodoverride.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 5, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(report.Issues))
	assert.True(t, report.HasFailedIssueReport())
	assert.True(t, report.Issues[0].HasFailed())
	assert.True(t, report.Issues[1].HasFailed())
}
