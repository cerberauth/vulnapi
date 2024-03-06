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
	headers := &http.Header{}
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

	operation := request.NewOperation(url, method, headers, cookies, securitySchemes)

	assert.Equal(t, url, operation.Url)
	assert.Equal(t, method, operation.Method)
	assert.Equal(t, headers, operation.Headers)
	assert.Equal(t, cookies, operation.Cookies)
	assert.Equal(t, securitySchemes, operation.SecuritySchemes)
}

func TestNewOperationWithNoSecuritySchemes(t *testing.T) {
	url := "http://example.com"
	method := "GET"
	headers := &http.Header{}
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

	operation := request.NewOperation(url, method, headers, cookies, nil)

	assert.Equal(t, url, operation.Url)
	assert.Equal(t, method, operation.Method)
	assert.Equal(t, headers, operation.Headers)
	assert.Equal(t, cookies, operation.Cookies)
	assert.Len(t, operation.SecuritySchemes, 1)
}

func TestOperationCloneWithHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Content-Type", "application/json")

	operation := request.NewOperation("http://example.com", "GET", &headers, nil, nil)

	clonedOperation := operation.Clone()

	assert.Equal(t, operation.Url, clonedOperation.Url)
	assert.Equal(t, operation.Method, clonedOperation.Method)
	assert.Equal(t, operation.Headers, clonedOperation.Headers)
}

func TestOperationCloneWithCookies(t *testing.T) {
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

	operation := request.NewOperation("http://example.com", "GET", nil, cookies, nil)

	clonedOperation := operation.Clone()

	assert.Equal(t, operation.Url, clonedOperation.Url)
	assert.Equal(t, operation.Method, clonedOperation.Method)
	assert.Equal(t, operation.Cookies, clonedOperation.Cookies)
}

func TestOperationCloneWithSecuritySchemes(t *testing.T) {
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}

	operation := request.NewOperation("http://example.com", "GET", nil, nil, securitySchemes)

	clonedOperation := operation.Clone()

	assert.Equal(t, operation.Url, clonedOperation.Url)
	assert.Equal(t, operation.Method, clonedOperation.Method)
	assert.Equal(t, operation.SecuritySchemes, clonedOperation.SecuritySchemes)
}
