package request_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestNewOperation(t *testing.T) {
	url := "http://example.com"
	method := http.MethodGet
	header := http.Header{}
	cookies := []*http.Cookie{
		{
			Name:  "cookie1",
			Value: "value1",
		},
		{
			Name:  "cookie2",
			Value: "value2",
		},
	}
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}

	operation, err := request.NewOperation(request.DefaultClient, method, url, header, cookies, securitySchemes)

	assert.NoError(t, err)
	assert.Equal(t, url, operation.Request.URL.String())
	assert.Equal(t, method, operation.Request.Method)
	assert.Equal(t, header, operation.Request.Header)
	assert.Equal(t, securitySchemes, operation.SecuritySchemes)
}

func TestOperation_IsReachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	url := server.URL
	r, _ := request.NewRequest(request.DefaultClient, http.MethodGet, url, nil)
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation := request.NewOperationFromRequest(r, securitySchemes)

	err := operation.IsReachable()

	assert.NoError(t, err)
}

func TestOperation_IsReachableWhenNotReachable(t *testing.T) {
	r, _ := request.NewRequest(request.DefaultClient, http.MethodGet, "http://localhost:8009", nil)
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation := request.NewOperationFromRequest(r, securitySchemes)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), ":8009: connect: connection refused")
}

func TestOperation_IsReachableWhenHTTPsAndNoPort(t *testing.T) {
	r, _ := request.NewRequest(request.DefaultClient, http.MethodGet, "https://localhost", nil)
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation := request.NewOperationFromRequest(r, securitySchemes)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), ":443: connect: connection refused")
}

func TestOperation_IsReachableWhenHTTPAndNoPort(t *testing.T) {
	r, _ := request.NewRequest(request.DefaultClient, http.MethodGet, "http://localhost", nil)
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation := request.NewOperationFromRequest(r, securitySchemes)

	err := operation.IsReachable()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), ":80: connect: connection refused")
}

func TestNewOperationFromRequest(t *testing.T) {
	r, _ := request.NewRequest(request.DefaultClient, http.MethodGet, "http://example.com", nil)
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation := request.NewOperationFromRequest(r, securitySchemes)

	assert.Equal(t, r, operation.Request)
	assert.Equal(t, securitySchemes, operation.SecuritySchemes)
}

func TestOperationCloneWithSecuritySchemes(t *testing.T) {
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}

	operation, err := request.NewOperation(request.DefaultClient, http.MethodGet, "http://example.com", nil, nil, securitySchemes)

	clonedOperation := operation.Clone()

	assert.NoError(t, err)
	assert.Equal(t, operation.Request, clonedOperation.Request)
	assert.Equal(t, operation.SecuritySchemes, clonedOperation.SecuritySchemes)
}

func TestOperation_WithOpenapiOperation(t *testing.T) {
	operation := &request.Operation{}
	path := "/test"
	openapiOperation := openapi3.Operation{
		OperationID: "testOperation",
		Tags:        []string{"tag1", "tag2"},
	}

	operation.WithOpenapiOperation(path, openapiOperation)

	assert.Equal(t, path, operation.GetPath())
	assert.Equal(t, openapiOperation.OperationID, operation.GetID())
	assert.Equal(t, openapiOperation.Tags, operation.GetTags())
}

func TestOperation_SetPath(t *testing.T) {
	operation := &request.Operation{}

	operation.SetPath("/test")

	assert.Equal(t, "/test", operation.GetPath())
}

func TestOperation_SetId(t *testing.T) {
	operation := &request.Operation{}

	operation.SetID("testOperation")

	assert.Equal(t, "testOperation", operation.GetID())
}

func TestOperation_SetTags(t *testing.T) {
	operation := &request.Operation{}

	operation.SetTags([]string{"tag1", "tag2"})

	assert.Equal(t, []string{"tag1", "tag2"}, operation.GetTags())
}

func TestMarshalJSON(t *testing.T) {
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}

	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://example.com", nil, nil, securitySchemes)

	_, err := json.Marshal(operation)

	assert.NoError(t, err)
}
