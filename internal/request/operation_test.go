package request_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestOperation_Clone(t *testing.T) {
	headers := http.Header{}
	headers.Add("Content-Type", "application/json")

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

	operation := request.Operation{
		Url:     "http://example.com",
		Method:  "GET",
		Headers: &headers,
		Cookies: cookies,
	}

	clonedOperation := operation.Clone()

	assert.Equal(t, operation.Url, clonedOperation.Url)
	assert.Equal(t, operation.Method, clonedOperation.Method)
	assert.Equal(t, operation.Headers, clonedOperation.Headers)
	assert.Equal(t, operation.Cookies, clonedOperation.Cookies)
}
