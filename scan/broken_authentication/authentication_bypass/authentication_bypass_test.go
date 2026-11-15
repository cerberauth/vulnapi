package authenticationbypass_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	authenticationbypass "github.com/cerberauth/vulnapi/scan/broken_authentication/authentication_bypass"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runAuthBypassCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return authenticationbypass.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
}

func evalAuthBypassSkip(op *operation.Operation) string {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return authenticationbypass.Check.Skip.EvalResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, harnessx.NewStaticResultStore())
}

func TestAuthBypassScanHandler_Skip_WithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})

	assert.NotEmpty(t, evalAuthBypassSkip(op))
}

func TestAuthBypassScanHandler_Failed_WhenOKResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("default", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	result, err := runAuthBypassCheck(op)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}

func TestAuthBypassScanHandler_Passed_WhenUnauthorizedResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("default", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	result, err := runAuthBypassCheck(op)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestAuthBypassScanHandler_Skip_WithOptionalSecurityRequirement(t *testing.T) {
	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{
		auth.MustNewAuthorizationBearerSecurityScheme("default", &token),
		auth.MustNewNoAuthSecurityScheme(),
	})

	assert.Equal(t, "operation declares an optional security requirement", evalAuthBypassSkip(op))
}

func TestAuthBypassScanHandler_ComparesWithAuthenticatedResponse(t *testing.T) {
	testCases := []struct {
		name       string
		anonymous  http.HandlerFunc
		vulnerable bool
	}{
		{
			name: "same protected response",
			anonymous: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":1}`))
			},
			vulnerable: true,
		},
		{
			name: "redirect to login page",
			anonymous: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/login", http.StatusFound)
			},
			vulnerable: false,
		},
		{
			name: "catch-all html page",
			anonymous: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<html>login</html>"))
			},
			vulnerable: false,
		},
		{
			name: "unauthorized",
			anonymous: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			vulnerable: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					w.Header().Set("Content-Type", "text/html")
					_, _ = w.Write([]byte("<html>login</html>"))
					return
				}
				if r.Header.Get("Authorization") == "Bearer token" {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"id":1}`))
					return
				}
				tc.anonymous(w, r)
			}))
			defer server.Close()

			token := "token"
			op := operation.MustNewOperation(http.MethodGet, server.URL+"/profile", nil, nil)
			op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})

			result, err := runAuthBypassCheck(op)

			require.NoError(t, err)
			f, ok := harnessx.DataAs[*finding.Finding](result)
			assert.Equal(t, tc.vulnerable, ok)
			if ok {
				assert.Empty(t, f.Attempt.Request.Header.Get("Authorization"))
				assert.NotNil(t, f.Attempt.Response)
			}
		})
	}
}
