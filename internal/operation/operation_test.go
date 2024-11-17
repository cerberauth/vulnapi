package operation_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	assert.Equal(t, "unsupported scheme", err.Error())
}

func TestNewOperationFromRequest(t *testing.T) {
	r, _ := request.NewRequest(http.MethodGet, "http://example.com", nil, nil)
	r.WithHeader(http.Header{
		"Content-Type": []string{"application/json"},
	})
	r.WithCookies([]*http.Cookie{
		{
			Name:  "cookie1",
			Value: "value1",
		},
	})
	operation, err := operation.NewOperationFromRequest(r)

	assert.NoError(t, err)
	assert.Equal(t, r.HttpRequest.URL.String(), operation.URL.String())
	assert.Equal(t, r.HttpRequest.Method, operation.Method)
	assert.Equal(t, r.HttpRequest.Header, operation.Header)
	assert.Equal(t, r.HttpRequest.Cookies(), operation.Cookies)
}

func TestNewOperationFromRequest_WithBody(t *testing.T) {
	body := strings.NewReader("test")
	r, _ := request.NewRequest(http.MethodPost, "http://example.com", body, nil)
	header := http.Header{}
	r.WithHeader(header)
	cookies := []*http.Cookie{}
	r.WithCookies(cookies)
	operation, err := operation.NewOperationFromRequest(r)

	assert.NoError(t, err)
	assert.Equal(t, r.HttpRequest.URL.String(), operation.URL.String())
	assert.Equal(t, r.HttpRequest.Method, operation.Method)
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
