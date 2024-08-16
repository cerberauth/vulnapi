package openapi_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
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
