package request_test

import (
	"bytes"
	"io"
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
	body := io.NopCloser(bytes.NewReader([]byte("test")))

	request, err := request.NewRequest(method, url, body, nil)

	assert.NoError(t, err)
	assert.Equal(t, method, request.Method)
	assert.Equal(t, url, request.URL.String())
	assert.Equal(t, body, request.Body)
}

func TestWithHeader(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	header := http.Header{
		"Content-Type": []string{"application/json"},
	}

	request, err := request.NewRequest(method, url, nil, nil)
	request = request.WithHeader(header)

	assert.NoError(t, err)
	assert.Equal(t, header.Get("Content-Type"), request.Request.Header.Get("Content-Type"))
}

func TestWithHTTPCookies(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	cookies := []*http.Cookie{{
		Name:  "cookie1",
		Value: "value1",
	}}

	request, err := request.NewRequest(method, url, nil, nil)
	request = request.WithCookies(cookies)

	assert.NoError(t, err)
	assert.Equal(t, cookies[0].Name, request.Request.Cookies()[0].Name)
	assert.Equal(t, cookies[0].Value, request.Request.Cookies()[0].Value)
}

func TestWithSecurityScheme(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	token := "token"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))

	request, err := request.NewRequest(method, url, nil, nil)
	request = request.WithSecurityScheme(securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, "Bearer "+token, request.Request.Header.Get("Authorization"))
}

func TestDo(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	request, _ := request.NewRequest(method, url, nil, nil)
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
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	header := http.Header{
		"X-Test": []string{"test"},
	}
	request, _ := request.NewRequest(method, url, nil, nil)
	request = request.WithHeader(header)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, header.Get("X-Test"), req.Header.Get("X-Test"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestDoWithClientHeaders(t *testing.T) {
	method := http.MethodGet
	url := "http://localhost:8080/"
	header := http.Header{
		"X-Test": []string{"test"},
	}
	client := request.NewClient(request.NewClientOptions{
		Header: header,
	})

	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	request, _ := request.NewRequest(method, url, nil, client)
	request = request.WithHeader(header)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, header.Get("X-Test"), req.Header.Get("X-Test"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestDoWithBody(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	body := []byte(`{"key": "value"}`)
	method := http.MethodPost
	url := "http://localhost:8080/"
	request, _ := request.NewRequest(method, url, bytes.NewReader(body), client)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		reqBody, _ := io.ReadAll(req.Body)

		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, body, reqBody)

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	response, err := request.Do()

	assert.NoError(t, err)
	assert.NotNil(t, response)
}

func TestDoWithSecuritySchemeHeaders(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	token := "token"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	request, _ := request.NewRequest(method, url, nil, client)
	request = request.WithSecurityScheme(securityScheme)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, "Bearer "+token, req.Header.Get("Authorization"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	_, err := request.Do()

	assert.NoError(t, err)
}

func TestDoWithHeadersSecuritySchemeHeaders(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	header := http.Header{
		"X-Test":        []string{"test"},
		"Authorization": []string{"Bearer othertoken"},
	}
	token := "token"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	request, _ := request.NewRequest(method, url, nil, client)
	request = request.WithHeader(header)
	request = request.WithSecurityScheme(securityScheme)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, header.Get("X-Test"), req.Header.Get("X-Test"))
		assert.Equal(t, "Bearer "+token, req.Header.Get("Authorization"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	_, err := request.Do()

	assert.NoError(t, err)
}

func TestDoWithCookiesSecuritySchemeHeaders(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	cookies := []*http.Cookie{{
		Name:  "cookie1",
		Value: "value1",
	}}
	token := "token"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	request, _ := request.NewRequest(method, url, nil, client)
	request = request.WithCookies(cookies)
	request = request.WithSecurityScheme(securityScheme)

	httpmock.RegisterResponder(method, url, func(req *http.Request) (*http.Response, error) {
		assert.Equal(t, method, req.Method)
		assert.Equal(t, url, req.URL.String())
		assert.Equal(t, "vulnapi", req.Header.Get("User-Agent"))
		assert.Equal(t, cookies[0].Name, req.Cookies()[0].Name)
		assert.Equal(t, cookies[0].Value, req.Cookies()[0].Value)
		assert.Equal(t, "Bearer "+token, req.Header.Get("Authorization"))

		return httpmock.NewBytesResponse(http.StatusNoContent, nil), nil
	})

	_, err := request.Do()

	assert.NoError(t, err)
}

func TestDoWithCookies(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	method := http.MethodGet
	url := "http://localhost:8080/"
	cookies := []*http.Cookie{{
		Name:  "cookie1",
		Value: "value1",
	}}
	request, _ := request.NewRequest(method, url, nil, client)
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
