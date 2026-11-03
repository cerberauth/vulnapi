package httpheaderscorsoriginreflection_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpheaderscorsoriginreflection "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_cors_origin_reflection"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httpheaderscorsoriginreflection.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
}

func newOperation(t *testing.T, responder httpmock.Responder) *operation.Operation {
	t.Helper()
	client := request.NewClient(request.NewClientOptions{})
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), responder)
	return op
}

func reflectingResponder(credentials string) httpmock.Responder {
	return func(req *http.Request) (*http.Response, error) {
		resp := httpmock.NewStringResponse(http.StatusOK, "OK")
		resp.Header.Set("Access-Control-Allow-Origin", req.Header.Get("Origin"))
		if credentials != "" {
			resp.Header.Set("Access-Control-Allow-Credentials", credentials)
		}
		return resp, nil
	}
}

func TestCORSOriginReflection_Skipped_WhenCORSNotConfigured(t *testing.T) {
	op := newOperation(t, httpmock.NewStringResponder(http.StatusOK, "OK"))

	result, err := runCheck(op)

	require.NoError(t, err)
	assert.True(t, result.Skipped)
}

func TestCORSOriginReflection_Failed_WhenOriginReflectedWithCredentials(t *testing.T) {
	op := newOperation(t, reflectingResponder("true"))

	result, err := runCheck(op)

	require.NoError(t, err)
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	assert.Equal(t, "Access-Control-Allow-Origin", f.Parameter)
	// the Origin header is not added to the shared operation
	assert.Empty(t, op.Header.Get("Origin"))
}

func TestCORSOriginReflection_Passed_WhenOriginReflectedWithoutCredentials(t *testing.T) {
	op := newOperation(t, reflectingResponder(""))

	result, err := runCheck(op)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestCORSOriginReflection_Passed_WhenOriginNotReflected(t *testing.T) {
	op := newOperation(t, func(req *http.Request) (*http.Response, error) {
		resp := httpmock.NewStringResponse(http.StatusOK, "OK")
		resp.Header.Set("Access-Control-Allow-Origin", "https://app.example.com")
		resp.Header.Set("Access-Control-Allow-Credentials", "true")
		return resp, nil
	})

	result, err := runCheck(op)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}
