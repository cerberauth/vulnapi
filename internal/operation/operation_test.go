package operation_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestNewOperation(t *testing.T) {
	url := "http://example.com"
	method := http.MethodGet
	body := bytes.NewBufferString("test")

	operation, err := operation.NewOperation(http.MethodGet, url, body, nil)

	assert.NoError(t, err)
	assert.Equal(t, url, operation.URL.String())
	assert.Equal(t, method, operation.Method)
	assert.Equal(t, []byte("test"), operation.Body)
}

func TestMustNewOperation(t *testing.T) {
	t.Run("ValidOperation", func(t *testing.T) {
		url := "http://example.com"
		method := http.MethodGet
		body := bytes.NewBufferString("test")

		operation := operation.MustNewOperation(method, url, body, nil)

		assert.NotNil(t, operation)
		assert.Equal(t, url, operation.URL.String())
		assert.Equal(t, method, operation.Method)
		assert.Equal(t, []byte("test"), operation.Body)
	})

	t.Run("InvalidURL", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic for invalid URL, but did not panic")
			}
		}()

		operation.MustNewOperation(http.MethodGet, ":", nil, nil)
	})
}

func TestOperation_IsReachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	url := server.URL
	operation, _ := operation.NewOperation(http.MethodGet, url, nil, nil)
	err := operation.IsReachable()

	assert.NoError(t, err)
}

func TestOperation_IsReachableWhenNotReachable(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8009", nil, nil)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), ":8009: connect: connection refused")
}

func TestOperation_IsReachableWhenHTTPs(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodGet, "https://localhost:443", nil, nil)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connect: connection refused")
}

func TestOperation_IsReachableWhenHTTPsAndNoPort(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodGet, "https://localhost", nil, nil)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), ":443: connect: connection refused")
}

func TestOperation_IsReachableWhenHTTPAndNoPort(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost", nil, nil)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), ":80: connect: connection refused")
}

func TestOperation_IsReachableWhenUnsupportedScheme(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodGet, "ftp://localhost", nil, nil)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Equal(t, "unsupported scheme: ftp", err.Error())
}

func TestNewOperationFromHTTPRequest(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{
		Name:  "cookie1",
		Value: "value1",
	})
	operation, err := operation.NewOperationFromHTTPRequest(r)

	assert.NoError(t, err)
	assert.Equal(t, r.URL.String(), operation.URL.String())
	assert.Equal(t, r.Method, operation.Method)
	assert.Equal(t, r.Header, operation.Header)
	assert.Equal(t, r.Cookies(), operation.Cookies)
}

func TestNewOperationFromHTTPRequest_WithBody(t *testing.T) {
	body := strings.NewReader("test")
	r, _ := http.NewRequest(http.MethodPost, "http://example.com", body)
	operation, err := operation.NewOperationFromHTTPRequest(r)

	assert.NoError(t, err)
	assert.Equal(t, r.URL.String(), operation.URL.String())
	assert.Equal(t, r.Method, operation.Method)
	assert.Equal(t, []byte("test"), operation.Body)
}

func TestOperation_GetSecurityScheme(t *testing.T) {
	t.Run("NoSecuritySchemes", func(t *testing.T) {
		operation := &operation.Operation{}
		expectedScheme := auth.MustNewNoAuthSecurityScheme()

		scheme := operation.GetSecurityScheme()

		assert.Equal(t, expectedScheme, scheme)
	})

	t.Run("WithSecuritySchemes", func(t *testing.T) {
		expectedScheme := auth.MustNewNoAuthSecurityScheme()
		operation := &operation.Operation{
			SecuritySchemes: []*auth.SecurityScheme{expectedScheme},
		}

		scheme := operation.GetSecurityScheme()

		assert.Equal(t, expectedScheme, scheme)
	})
}

func TestOperationCloneWithSecuritySchemes(t *testing.T) {
	securitySchemes := []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}

	operation := operation.MustNewOperation(http.MethodGet, "http://example.com", nil, nil)
	operation.SetSecuritySchemes(securitySchemes)

	clonedOperation, err := operation.Clone()

	assert.NoError(t, err)
	assert.Equal(t, operation.URL, clonedOperation.URL)
	assert.Equal(t, operation.Method, clonedOperation.Method)
	assert.Equal(t, operation.SecuritySchemes, clonedOperation.SecuritySchemes)
}

func TestOperation_WithOpenapiOperation(t *testing.T) {
	operation, _ := operation.NewOperation(http.MethodGet, "http://example.com", nil, nil)
	openapiOperation := &openapi3.Operation{
		OperationID: "testOperation",
	}

	operation.WithOpenapiOperation("/", openapiOperation)

	assert.Equal(t, openapiOperation.OperationID, operation.GetID())
}

func TestOperation_WithOpenapiOperation_WithoutOperationID(t *testing.T) {
	operation, _ := operation.NewOperation(http.MethodGet, "http://example.com/resource", nil, nil)
	openapiOperation := &openapi3.Operation{}

	operation.WithOpenapiOperation("/resource", openapiOperation)

	assert.Equal(t, "getResource", operation.GetID())
}

func TestOperation_WithOpenapiOperation_WithoutOperationIDAndParameters(t *testing.T) {
	operation, _ := operation.NewOperation(http.MethodGet, "http://example.com/resource", nil, nil)
	openapiOperation := &openapi3.Operation{}

	operation.WithOpenapiOperation("/resource/{id}", openapiOperation)

	assert.Equal(t, "getResourceId", operation.GetID())
}

func TestOperation_WithHeader(t *testing.T) {
	operation := &operation.Operation{}
	header := http.Header{
		"Content-Type": []string{"application/json"},
	}

	operation.WithHeader(header)

	assert.Equal(t, header, operation.Header)
}

func TestOperation_WithCookies(t *testing.T) {
	operation := &operation.Operation{}
	cookies := []*http.Cookie{{
		Name:  "cookie1",
		Value: "value1",
	}}

	operation.WithCookies(cookies)

	assert.Equal(t, cookies, operation.Cookies)
}

func TestOperation_GenerateID(t *testing.T) {
	tests := []struct {
		method   string
		url      string
		expected string
	}{
		{http.MethodGet, "http://example.com/", "getRoot"},
		{http.MethodGet, "http://example.com/path/to/resource", "getPathToResource"},
		{http.MethodPost, "http://example.com/path/to/resource", "postPathToResource"},
		{http.MethodPut, "http://example.com/path/to/resource", "putPathToResource"},
		{http.MethodDelete, "http://example.com/path/to/resource", "deletePathToResource"},
		{http.MethodGet, "http://example.com/path/to/resource{[]}", "getPathToResource"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.url, func(t *testing.T) {
			operation, err := operation.NewOperation(tt.method, tt.url, nil, nil)
			assert.NoError(t, err)

			operation.GenerateID()

			assert.Equal(t, tt.expected, operation.GetID())
		})
	}
}

func TestOperation_SetId(t *testing.T) {
	operation := &operation.Operation{}

	operation.SetID("testOperation")

	assert.Equal(t, "testOperation", operation.GetID())
}

func TestMarshalJSON(t *testing.T) {
	operation, _ := operation.NewOperation(http.MethodGet, "http://example.com", nil, nil)

	_, err := json.Marshal(operation)

	assert.NoError(t, err)
}

func TestOperationCloneDoesNotShareMutableState(t *testing.T) {
	op := operation.MustNewOperation(http.MethodPost, "http://example.com", bytes.NewBufferString("body"), nil)
	op.Header.Set("X-Original", "value")
	op.Cookies = []*http.Cookie{{Name: "session", Value: "original"}}

	clonedOperation, err := op.Clone()
	assert.NoError(t, err)
	clonedOperation.Header.Set("X-HTTP-Method-Override", "DELETE")
	clonedOperation.Cookies[0].Value = "changed"
	clonedOperation.Body[0] = 'B'
	clonedOperation.URL.Path = "/changed"
	clonedOperation.SecuritySchemes[0] = nil

	assert.Empty(t, op.Header.Get("X-HTTP-Method-Override"))
	assert.Equal(t, "value", clonedOperation.Header.Get("X-Original"))
	assert.Equal(t, "original", op.Cookies[0].Value)
	assert.Equal(t, []byte("body"), op.Body)
	assert.Equal(t, "", op.URL.Path)
	assert.NotNil(t, op.SecuritySchemes[0])
}

func TestOperation_NewHTTPRequestAppliesClientHeadersAndCookies(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		Header:  http.Header{"X-Tenant": []string{"tenant"}, "X-Override": []string{"client"}},
		Cookies: []*http.Cookie{{Name: "session", Value: "client-session"}},
	})
	op := operation.MustNewOperation(http.MethodGet, "http://example.com", nil, client)
	op.Header.Set("X-Override", "operation")
	op.Cookies = []*http.Cookie{{Name: "csrf", Value: "operation-csrf"}}

	req, err := op.NewHTTPRequest(t.Context(), probe.WithHeader("Authorization", "Bearer token"))

	assert.NoError(t, err)
	assert.Equal(t, "tenant", req.Header.Get("X-Tenant"))
	assert.Equal(t, "operation", req.Header.Get("X-Override"))
	assert.Equal(t, "Bearer token", req.Header.Get("Authorization"))
	assert.Equal(t, request.DefaultUserAgent, req.Header.Get("User-Agent"))
	sessionCookie, err := req.Cookie("session")
	assert.NoError(t, err)
	assert.Equal(t, "client-session", sessionCookie.Value)
	csrfCookie, err := req.Cookie("csrf")
	assert.NoError(t, err)
	assert.Equal(t, "operation-csrf", csrfCookie.Value)
}

func TestOperation_NewHTTPRequestUserAgent(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{}).WithUserAgent("vulnapi/1.0.0")
	op := operation.MustNewOperation(http.MethodGet, "http://example.com", nil, client)

	req, err := op.NewHTTPRequest(t.Context())

	assert.NoError(t, err)
	assert.Equal(t, "vulnapi/1.0.0", req.Header.Get("User-Agent"))
	assert.Equal(t, "vulnapi/1.0.0", op.UserAgent())

	client.Header.Set("User-Agent", "custom-agent")
	req, err = op.NewHTTPRequest(t.Context())

	assert.NoError(t, err)
	assert.Equal(t, "custom-agent", req.Header.Get("User-Agent"))
	assert.Equal(t, "custom-agent", op.UserAgent())
}
