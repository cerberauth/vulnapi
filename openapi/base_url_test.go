package openapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseUrl(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)
	expectedURL, _ := url.Parse("http://localhost:8080/")

	baseURL := openapi.BaseUrl()

	assert.Equal(t, expectedURL, baseURL)
}

func TestBaseUrlWithInvalidURL(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: invalid-url}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)

	baseURL := openapi.BaseUrl()

	assert.Nil(t, baseURL)
}

func TestBaseUrlWithBasePath(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080/path'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)
	expectedURL, _ := url.Parse("http://localhost:8080/path")

	baseURL := openapi.BaseUrl()

	assert.Equal(t, expectedURL, baseURL)
}

func TestBaseUrlWithServerVariables(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: '{scheme}://{host}/{version}', variables: {scheme: {default: https}, host: {default: 'api.example.com'}, version: {default: v1}}}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)
	expectedURL, _ := url.Parse("https://api.example.com/v1")

	baseURL := openapi.BaseUrl()

	assert.Equal(t, expectedURL, baseURL)
}

func TestBaseUrlWithRelativeServerLoadedFromURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"openapi": "3.0.2", "servers": [{"url": "/api/v1"}], "paths": {"/": {"get": {"responses": {"204": {"description": "successful operation"}}}}}}`))
	}))
	defer server.Close()

	openapi, err := openapi.LoadOpenAPI(context.Background(), server.URL+"/docs/openapi.json")
	require.NoError(t, err)

	assert.Equal(t, server.URL+"/api/v1", openapi.BaseUrl().String())
}
