package httpmethodoverrideauthbypass_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	jwtop "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpmethodoverride "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override"
	httpmethodoverrideauthbypass "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override_auth_bypass"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func overrideStoreFor(t *testing.T, op *operation.Operation) harnessx.ResultStore {
	t.Helper()
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	result, err := httpmethodoverride.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
	require.NoError(t, err)
	result.CheckID = httpmethodoverride.Check.ID
	result.ResourceID = op.ID
	return harnessx.NewStaticResultStore(result)
}

func runAuthBypassCheck(op *operation.Operation, store harnessx.ResultStore) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httpmethodoverrideauthbypass.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, store)
}

func evalAuthBypassSkip(op *operation.Operation, store harnessx.ResultStore) string {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httpmethodoverrideauthbypass.Check.Skip.EvalResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, store)
}

func TestHTTPMethodOverrideAuthBypass_Skip_WithoutSecurityScheme(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})

	store := harnessx.NewStaticResultStore()
	assert.NotEmpty(t, evalAuthBypassSkip(op, store))
}

func TestHTTPMethodOverrideAuthBypass_Skip_WhenOverrideNotVulnerable(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte(""))
	require.NoError(t, err)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("securityScheme", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusMethodNotAllowed, nil))

	store := overrideStoreFor(t, op)
	assert.NotEmpty(t, evalAuthBypassSkip(op, store))
}

func TestHTTPMethodOverrideAuthBypass_Passed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte(""))
	require.NoError(t, err)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("securityScheme", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet && req.Header.Get("Authorization") == "Bearer "+string(token) {
			return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
		}
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet && req.Header.Get("Authorization") == "" {
			return httpmock.NewJsonResponse(http.StatusUnauthorized, nil)
		}
		return httpmock.NewJsonResponse(http.StatusMethodNotAllowed, nil)
	})

	store := overrideStoreFor(t, op)
	assert.Empty(t, evalAuthBypassSkip(op, store))

	result, err := runAuthBypassCheck(op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestHTTPMethodOverrideAuthBypass_Failed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte(""))
	require.NoError(t, err)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("securityScheme", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodHead, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-HTTP-Method-Override") == http.MethodGet {
			return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
		}
		return httpmock.NewJsonResponse(http.StatusMethodNotAllowed, nil)
	})

	store := overrideStoreFor(t, op)
	assert.Empty(t, evalAuthBypassSkip(op, store))

	result, err := runAuthBypassCheck(op, store)

	require.NoError(t, err)
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	assert.NotNil(t, f)
}
