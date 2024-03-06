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
	method := "GET"
	header := http.Header{}
	cookies := []http.Cookie{
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

	operation := request.NewOperation(url, method, header, cookies, securitySchemes)

	assert.Equal(t, url, operation.Request.URL.String())
	assert.Equal(t, method, operation.Request.Method)
	assert.Equal(t, header, operation.Request.Header)
	assert.Equal(t, securitySchemes, operation.SecuritySchemes)
}

func TestNewOperationWithNoSecuritySchemes(t *testing.T) {
	url := "http://example.com"
	method := "GET"
	header := http.Header{}
	cookies := []http.Cookie{
		{
			Name:  "cookie1",
			Value: "value1",
		},
		{
			Name:  "cookie2",
			Value: "value2",
		},
	}

	operation := request.NewOperation(url, method, header, cookies, nil)

	assert.Equal(t, url, operation.Request.URL.String())
	assert.Equal(t, method, operation.Request.Method)
	assert.Equal(t, header, operation.Request.Header)
	assert.Len(t, operation.SecuritySchemes, 1)
}

func TestNewOperationFromRequest(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}

	operation := request.NewOperationFromRequest(r, securitySchemes)

	assert.Equal(t, r, operation.Request)
	assert.Equal(t, securitySchemes, operation.SecuritySchemes)
}

func TestOperationCloneWithSecuritySchemes(t *testing.T) {
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}

	operation := request.NewOperation("http://example.com", "GET", nil, nil, securitySchemes)

	clonedOperation := operation.Clone()

	assert.Equal(t, operation.Request, clonedOperation.Request)
	assert.Equal(t, operation.SecuritySchemes, clonedOperation.SecuritySchemes)
}
