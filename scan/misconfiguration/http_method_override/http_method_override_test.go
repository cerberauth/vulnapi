package httpmethodoverride_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/harnessx"
	jwtop "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpmethodoverride "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runHTTPMethodOverrideCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httpmethodoverride.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
}

func TestHTTPMethodOverrideScanHandler(t *testing.T) {
	value, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte(""))
	require.NoError(t, err)
	tests := []struct {
		name           string
		operation      *operation.Operation
		securityScheme *auth.SecurityScheme
	}{
		{
			name:           "MethodNotAllowed",
			operation:      operation.MustNewOperation(http.MethodGet, "http://example.com", nil, nil),
			securityScheme: auth.MustNewNoAuthSecurityScheme(),
		},
		{
			name:           "MethodOverrideDetected",
			operation:      operation.MustNewOperation(http.MethodPost, "http://example.com/test", nil, nil),
			securityScheme: auth.MustNewNoAuthSecurityScheme(),
		},
		{
			name:           "AuthenticationBypassDetected",
			operation:      operation.MustNewOperation(http.MethodPost, "http://example.com/test", nil, nil),
			securityScheme: auth.MustNewAuthorizationBearerSecurityScheme("securityScheme", &value),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.operation.SetSecuritySchemes([]*auth.SecurityScheme{tt.securityScheme})
			_, err := runHTTPMethodOverrideCheck(tt.operation)
			if err != nil {
				t.Errorf("Check.RunResource() error = %v", err)
				return
			}
		})
	}
}

func TestHTTPMethodOverrideScanHandler_When_Error(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	result, err := runHTTPMethodOverrideCheck(op)

	require.Error(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestHTTPMethodOverrideScanHandler_Skipped_WhenInitialMethodNotAllowed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusMethodNotAllowed, nil))

	result, err := runHTTPMethodOverrideCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, result.Skipped)
}

func TestHTTPMethodOverrideScanHandler_Passed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusMethodNotAllowed, nil))

	result, err := runHTTPMethodOverrideCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 12, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestHTTPMethodOverrideScanHandler_Failed_With_Header(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet {
			return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
		}
		return httpmock.NewJsonResponse(http.StatusMethodNotAllowed, nil)
	})

	result, err := runHTTPMethodOverrideCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 4, httpmock.GetTotalCallCount())
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	winningOp, ok := f.Data.(*operation.Operation)
	require.True(t, ok)
	assert.NotNil(t, winningOp)
}

func TestHTTPMethodOverrideScanHandler_Failed_With_Query_Parameter(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusMethodNotAllowed, nil))

	urlWithOverrideQuery, _ := url.Parse(op.URL.String())
	newQueryValues := urlWithOverrideQuery.Query()
	newQueryValues.Set("_method", http.MethodGet)
	urlWithOverrideQuery.RawQuery = newQueryValues.Encode()
	httpmock.RegisterResponder(http.MethodPost, urlWithOverrideQuery.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	result, err := runHTTPMethodOverrideCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 9, httpmock.GetTotalCallCount())
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	winningOp, ok := f.Data.(*operation.Operation)
	require.True(t, ok)
	assert.NotNil(t, winningOp)
}
