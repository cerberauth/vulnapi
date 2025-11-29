package openapi_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
)

func TestSecuritySchemeMap_WithoutSecurityComponents(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithUnknownSchemeType(t *testing.T) {
	expectedErr := openapi.NewErrUnsupportedSecuritySchemeType("other")
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: other}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithUnknownScheme(t *testing.T) {
	expectedErr := openapi.NewErrUnsupportedScheme("other")
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: other}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithUnknownBearerFormat(t *testing.T) {
	expectedErr := openapi.NewErrUnsupportedBearerFormat("other")
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: other}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.Error(t, err)
	assert.Equal(t, expectedErr, err)
	assert.Nil(t, result)
}

func TestSecuritySchemeMap_WithHTTPJWTBearer(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: JWT}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.HttpType, result["bearer_auth"].GetType())
	assert.Equal(t, auth.BearerScheme, result["bearer_auth"].GetScheme())
	assert.Equal(t, auth.JWTTokenFormat, *result["bearer_auth"].GetTokenFormat())
}

func TestSecuritySchemeMap_WithHTTPBearer(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.HttpType, result["bearer_auth"].GetType())
	assert.Equal(t, auth.BearerScheme, result["bearer_auth"].GetScheme())
}

func TestSecuritySchemeMap_WithoutHTTPJWTBearerAndDefaultValue(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: JWT}}}}`),
	)

	token := jwt.FakeJWT
	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues().WithDefault(&token))

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.HttpType, result["bearer_auth"].GetType())
	assert.Equal(t, auth.BearerScheme, result["bearer_auth"].GetScheme())
	assert.Equal(t, auth.JWTTokenFormat, *result["bearer_auth"].GetTokenFormat())
}

func TestSecuritySchemeMap_WithAPIKeyInHeader(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [{name: 'Authorization', in: header, required: true, schema: {type: string}}], responses: {'204': {description: successful operation}}, security: [{api_key_auth: []}]}}}, components: {securitySchemes: {api_key_auth: {type: apiKey, in: header, name: X-API-KEY}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.ApiKey, result["api_key_auth"].GetType())
	assert.Equal(t, auth.InHeader, *result["api_key_auth"].In)
}

func TestSecuritySchemeMap_WithInvalidValueType(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: JWT}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues().WithDefault(""))

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.HttpType, result["bearer_auth"].GetType())
	assert.Equal(t, auth.BearerScheme, result["bearer_auth"].GetScheme())
	assert.Equal(t, auth.JWTTokenFormat, *result["bearer_auth"].GetTokenFormat())
}

func TestSecuritySchemeMap_WithOAuth(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{oauth_auth: []}]}}}, components: {securitySchemes: {oauth_auth: {type: oauth2}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.OAuth2, result["oauth_auth"].GetType())
	assert.Equal(t, auth.OAuthScheme, result["oauth_auth"].GetScheme())
}

func TestSecuritySchemeMap_WithOAuthAndAuthorizationCodeFlow(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{oauth_auth: []}]}}}, components: {securitySchemes: {oauth_auth: {type: oauth2, flows: {authorizationCode: {tokenUrl: 'http://localhost:8080/token', refreshUrl: 'http://localhost:8080/refresh'}}}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.OAuth2, result["oauth_auth"].GetType())
	assert.Equal(t, auth.OAuthScheme, result["oauth_auth"].GetScheme())
	assert.Equal(t, &auth.OAuthConfig{
		TokenURL:   "http://localhost:8080/token",
		RefreshURL: "http://localhost:8080/refresh",
	}, result["oauth_auth"].GetConfig())
}

func TestSecuritySchemeMap_WithOAuthAndImplicitFlow(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{oauth_auth: []}]}}}, components: {securitySchemes: {oauth_auth: {type: oauth2, flows: {implicit: {tokenUrl: 'http://localhost:8080/token', refreshUrl: 'http://localhost:8080/refresh'}}}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.OAuth2, result["oauth_auth"].GetType())
	assert.Equal(t, auth.OAuthScheme, result["oauth_auth"].GetScheme())
	assert.Equal(t, &auth.OAuthConfig{
		TokenURL:   "http://localhost:8080/token",
		RefreshURL: "http://localhost:8080/refresh",
	}, result["oauth_auth"].GetConfig())
}

func TestSecuritySchemeMap_WithOAuthAndClientCredentialsFlow(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{oauth_auth: []}]}}}, components: {securitySchemes: {oauth_auth: {type: oauth2, flows: {clientCredentials: {tokenUrl: 'http://localhost:8080/token', refreshUrl: 'http://localhost:8080/refresh'}}}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.OAuth2, result["oauth_auth"].GetType())
	assert.Equal(t, auth.OAuthScheme, result["oauth_auth"].GetScheme())
	assert.Equal(t, &auth.OAuthConfig{
		TokenURL:   "http://localhost:8080/token",
		RefreshURL: "http://localhost:8080/refresh",
	}, result["oauth_auth"].GetConfig())
}

func TestSecuritySchemeMap_WithOpenIDConnect(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{oidc_auth: []}]}}}, components: {securitySchemes: {oidc_auth: {type: openIdConnect}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, auth.OAuth2, result["oidc_auth"].GetType())
	assert.Equal(t, auth.OAuthScheme, result["oidc_auth"].GetScheme())
	assert.Nil(t, result["oidc_auth"].GetConfig())
}
