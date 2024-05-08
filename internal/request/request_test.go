package request_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestNewRequest(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"

	request, err := request.NewRequest(method, url, nil)

	assert.NoError(t, err)
	assert.Equal(t, method, request.Method)
	assert.Equal(t, url, request.URL.String())
}

func TestWithHTTPHeaders(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	headers := http.Header{
		"Content-Type": []string{"application/json"},
	}

	request, err := request.NewRequest(method, url, nil)
	request = request.WithHTTPHeaders(headers)

	assert.NoError(t, err)
	assert.Equal(t, headers, request.Header)
}

func TestWithHTTPCookies(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	cookies := []*http.Cookie{{
		Name:  "cookie1",
		Value: "value1",
	}}

	request, err := request.NewRequest(method, url, nil)
	request = request.WithCookies(cookies)

	assert.NoError(t, err)
	assert.Equal(t, cookies, request.Cookies)
}

func TestWithSecurityScheme(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	securityScheme := auth.SecurityScheme(auth.NewNoAuthSecurityScheme())

	request, err := request.NewRequest(method, url, nil)
	request = request.WithSecurityScheme(&securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, &securityScheme, request.SecurityScheme)
}

func TestDo(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	request, _ := request.NewRequest(method, url, nil)
	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, http.StatusNoContent, response.StatusCode)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
}

func TestDoWithHeaders(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	header := http.Header{
		"Content-Type": []string{"application/json"},
		"X-Test":       []string{"test"},
	}
	request, _ := request.NewRequest(method, url, nil)
	request = request.WithHTTPHeaders(header)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, header.Get("Content-Type"), req.Header.Get("Content-Type"))
		assert.Equal(t, header.Get("X-Test"), req.Header.Get("X-Test"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestDoWithSecuritySchemeHeaders(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	token := "token"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	request, _ := request.NewRequest(method, url, nil)
	request = request.WithSecurityScheme(&securityScheme)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, "Bearer "+token, req.Header.Get("Authorization"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestDoWithHeadersSecuritySchemeHeaders(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	header := http.Header{
		"X-Test":        []string{"test"},
		"Authorization": []string{"Bearer othertoken"},
	}
	token := "token"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	request, _ := request.NewRequest(method, url, nil)
	request = request.WithHTTPHeaders(header)
	request = request.WithSecurityScheme(&securityScheme)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, header.Get("X-Test"), req.Header.Get("X-Test"))
		assert.Equal(t, "Bearer "+token, req.Header.Get("Authorization"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestDoWithCookies(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	cookies := []*http.Cookie{{
		Name:  "cookie1",
		Value: "value1",
	}}
	request, _ := request.NewRequest(method, url, nil)
	request = request.WithCookies(cookies)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Len(t, req.Cookies(), 1)
		assert.Equal(t, cookies[0].Name, req.Cookies()[0].Name)
		assert.Equal(t, cookies[0].Value, req.Cookies()[0].Value)

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestClone(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	request, _ := request.NewRequest(method, url, nil)
	clone := request.Clone(context.Background())

	assert.Equal(t, request.Method, clone.Method)
	assert.Equal(t, request.URL.String(), clone.URL.String())
}
