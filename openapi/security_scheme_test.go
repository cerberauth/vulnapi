package openapi_test

import (
	"context"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
)

func TestSecuritySchemeMap_WithoutSecurityComponents(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)

	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValues())

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithUnknownSchemeType(t *testing.T) {
	expectedErr := openapi.NewErrUnsupportedSecuritySchemeType("other")
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: other}}}}`),
	)

	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValues())

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithUnknownScheme(t *testing.T) {
	expectedErr := openapi.NewErrUnsupportedScheme("other")
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: other}}}}`),
	)

	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValues())

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithUnknownBearerFormat(t *testing.T) {
	expectedErr := openapi.NewErrUnsupportedBearerFormat("other")
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: other}}}}`),
	)

	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValues())

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithHTTPJWTBearer(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: JWT}}}}`),
	)

	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.IsType(t, &auth.JWTBearerSecurityScheme{}, result["bearer_auth"])
}

func TestSecuritySchemeMap_WithHTTPBearer(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer}}}}`),
	)

	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.IsType(t, &auth.BearerSecurityScheme{}, result["bearer_auth"])
}

func TestSecuritySchemeMap_WithoutHTTPJWTBearerAndDefaultValue(t *testing.T) {
	openapi, _ := openapi.LoadFromData(
		context.Background(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: JWT}}}}`),
	)

	token := jwt.FakeJWT
	result, err := openapi.SecuritySchemeMap(auth.NewSecuritySchemeValuesWithDefault(&token))

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.IsType(t, &auth.JWTBearerSecurityScheme{}, result["bearer_auth"])
}
