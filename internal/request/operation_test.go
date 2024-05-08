package request_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
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

func TestNewOperationWithNoSecuritySchemes(t *testing.T) {
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

	operation, err := request.NewOperation(request.DefaultClient, method, url, header, cookies, nil)

	assert.NoError(t, err)
	assert.Equal(t, url, operation.Request.URL.String())
	assert.Equal(t, method, operation.Request.Method)
	assert.Equal(t, header, operation.Request.Header)
	assert.Len(t, operation.SecuritySchemes, 1)
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
