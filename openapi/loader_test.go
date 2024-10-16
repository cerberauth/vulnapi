package openapi_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestLoadOpenAPIWithEmptyURLOrPath(t *testing.T) {
	_, err := openapi.LoadOpenAPI(context.Background(), "")
	expectedErr := errors.New("url or path must not be empty")

	assert.Equal(t, expectedErr, err)
}

func TestLoadOpenAPIWithInvalidURL(t *testing.T) {
	invalidURL := "invalid-url"
	_, err := openapi.LoadOpenAPI(context.Background(), invalidURL)

	expectedErr := fmt.Errorf("the openapi file has not been found on %s", invalidURL)

	assert.Equal(t, expectedErr, err)
}

func TestLoadOpenAPIWithValidURL(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	validURL := "http://example.com/openapi.yaml"
	httpmock.RegisterResponder(http.MethodGet, validURL, httpmock.ResponderFromResponse(
		httpmock.NewStringResponse(200, "openapi: 3.0.0"),
	))

	_, err := openapi.LoadOpenAPI(context.Background(), validURL)

	assert.NoError(t, err)
}

func TestLoadOpenAPIWithNonExistentFile(t *testing.T) {
	nonExistentFile := "/path/to/nonexistent.yaml"
	_, err := openapi.LoadOpenAPI(context.Background(), nonExistentFile)

	expectedErr := fmt.Errorf("the openapi file has not been found on %s", nonExistentFile)

	assert.Equal(t, expectedErr, err)
}

func TestLoadOpenAPIWithValidFilePath(t *testing.T) {
	validFilePath := "../test/stub/simple_http_bearer_jwt.openapi.yaml"
	_, err := openapi.LoadOpenAPI(context.Background(), validFilePath)

	assert.NoError(t, err)
}
