package openapi_test

import (
	"context"
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
)

func TestValidate(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, info: {title: API, version: '1.0', contact: {}}, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: successful operation}}}}}}`),
	)

	err := openapi.Validate(context.Background())

	assert.NoError(t, err)
}

func TestValidateWithoutServers(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, info: {title: API, version: '1.0', contact: {}}, paths: {/: {get: {responses: {'204': {description: successful operation}}}}}}`),
	)

	err := openapi.Validate(context.Background())

	assert.Error(t, err)
	assert.EqualError(t, err, "no valid base url has been found in OpenAPI file")
}

func TestValidateWithInvalidBaseUrl(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, info: {title: API, version: '1.0', contact: {}}, servers: [{url: 'invalid-url'}], paths: {/: {get: {responses: {'204': {description: successful operation}}}}}}`),
	)

	err := openapi.Validate(context.Background())

	assert.Error(t, err)
	assert.EqualError(t, err, "no valid base url has been found in OpenAPI file")
}
