package openapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	jwtop "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSecuritySchemeMap_SkipsUnknownSchemeType(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {other_auth: {type: other}, bearer_auth: {type: http, scheme: bearer}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.NotContains(t, result, "other_auth")
	assert.Contains(t, result, "bearer_auth")
}

func TestSecuritySchemeMap_SkipsUnknownScheme(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{digest_auth: []}]}}}, components: {securitySchemes: {digest_auth: {type: http, scheme: digest}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestUnsupportedSecuritySchemeErrors(t *testing.T) {
	assert.ErrorIs(t, openapi.NewErrUnsupportedScheme("digest"), openapi.ErrUnsupportedSecurityScheme)
	assert.ErrorIs(t, openapi.NewErrUnsupportedSecuritySchemeType("mutualtls"), openapi.ErrUnsupportedSecurityScheme)
}

func TestSecuritySchemeMap_WithOpaqueBearerFormat(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {parameters: [], responses: {'204': {description: successful operation}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer, bearerFormat: opaque}}}}`),
	)

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewEmptySecuritySchemeValues())

	assert.NoError(t, err)
	assert.Equal(t, auth.BearerScheme, result["bearer_auth"].GetScheme())
	assert.Nil(t, result["bearer_auth"].GetTokenFormat())
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

	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte(""))
	require.NoError(t, err)
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
	assert.Equal(t, "X-API-KEY", result["api_key_auth"].GetName())
}

func TestSecuritySchemeMap_WithAPIKeyInCookieAndQuery(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(
		t.Context(),
		[]byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: successful operation}}, security: [{cookie_auth: []}, {query_auth: []}]}}}, components: {securitySchemes: {cookie_auth: {type: apiKey, in: cookie, name: session}, query_auth: {type: apiKey, in: query, name: api_key}}}}`),
	)
	cookieValue := "cookie-value"
	queryValue := "query-value"

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewSecuritySchemeValues(map[string]interface{}{
		"cookie_auth": &cookieValue,
		"query_auth":  &queryValue,
	}))

	assert.NoError(t, err)
	assert.Equal(t, []*http.Cookie{{Name: "session", Value: cookieValue}}, result["cookie_auth"].GetCookies())
	assert.Equal(t, queryValue, result["query_auth"].GetQueryParams().Get("api_key"))
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
	assert.Equal(t, auth.OpenIdConnect, result["oidc_auth"].GetType())
	assert.Equal(t, auth.OAuthScheme, result["oidc_auth"].GetScheme())
	assert.Equal(t, &auth.OpenIDConnectConfig{}, result["oidc_auth"].GetConfig())
}

func TestSecuritySchemeMap_WithHTTPBasicValue(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{basic_auth: []}]}}}, components: {securitySchemes: {basic_auth: {type: http, scheme: basic}}}}`))
	value := "user:pa:ss"

	result, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewSecuritySchemeValues(map[string]interface{}{"basic_auth": &value}))

	require.NoError(t, err)
	credentials := result["basic_auth"].GetValidValue().(*auth.HTTPBasicCredentials)
	assert.Equal(t, "user", credentials.GetUsername())
	assert.Equal(t, "pa:ss", credentials.GetPassword())
}

func TestSecuritySchemeMap_WithInvalidHTTPBasicValue(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{basic_auth: []}]}}}, components: {securitySchemes: {basic_auth: {type: http, scheme: basic}}}}`))
	value := "user"

	_, err := openapiContract.SecuritySchemeMap(t.Context(), openapi.NewSecuritySchemeValues(map[string]interface{}{"basic_auth": &value}))

	assert.ErrorContains(t, err, "user:password")
}

func newTokenServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_, _ = w.Write([]byte(`{"token_endpoint":"` + "http://" + r.Host + `/token","jwks_uri":"http://` + r.Host + `/jwks"}`))
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + r.PostForm.Get("grant_type") + `-token","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSecuritySchemeMap_WithOAuth2ClientCredentialsFlow(t *testing.T) {
	tokenServer := newTokenServer(t)
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{oauth: []}]}}}, components: {securitySchemes: {oauth: {type: oauth2, flows: {clientCredentials: {tokenUrl: '`+tokenServer+`/token', scopes: {}}}}}}}`))
	values := openapi.NewEmptySecuritySchemeValues().WithCredentials(auth.NewCredentialRegistry(auth.CredentialOptions{ClientID: "client", ClientSecret: "secret"}))

	result, err := openapiContract.SecuritySchemeMap(t.Context(), values)

	require.NoError(t, err)
	assert.Equal(t, "client_credentials-token", result["oauth"].GetToken())
	assert.Equal(t, "Bearer client_credentials-token", result["oauth"].GetHeaders().Get("Authorization"))
}

func TestSecuritySchemeMap_WithOAuth2PasswordFlow(t *testing.T) {
	tokenServer := newTokenServer(t)
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{oauth: []}]}}}, components: {securitySchemes: {oauth: {type: oauth2, flows: {password: {tokenUrl: '`+tokenServer+`/token', scopes: {}}}}}}}`))
	values := openapi.NewEmptySecuritySchemeValues().WithCredentials(auth.NewCredentialRegistry(auth.CredentialOptions{ClientID: "client", Username: "user", Password: "pass"}))

	result, err := openapiContract.SecuritySchemeMap(t.Context(), values)

	require.NoError(t, err)
	assert.Equal(t, "password-token", result["oauth"].GetToken())
}

func TestSecuritySchemeMap_WithOpenIDConnectDiscovery(t *testing.T) {
	tokenServer := newTokenServer(t)
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{oidc: []}]}}}, components: {securitySchemes: {oidc: {type: openIdConnect, openIdConnectUrl: '`+tokenServer+`/.well-known/openid-configuration'}}}}`))
	values := openapi.NewEmptySecuritySchemeValues().WithCredentials(auth.NewCredentialRegistry(auth.CredentialOptions{ClientID: "client", ClientSecret: "secret"}))

	result, err := openapiContract.SecuritySchemeMap(t.Context(), values)

	require.NoError(t, err)
	assert.Equal(t, auth.OpenIdConnect, result["oidc"].GetType())
	assert.Equal(t, "client_credentials-token", result["oidc"].GetToken())
	assert.Equal(t, &auth.OpenIDConnectConfig{
		URL:      tokenServer + "/.well-known/openid-configuration",
		TokenURL: tokenServer + "/token",
		JWKSURL:  tokenServer + "/jwks",
	}, result["oidc"].GetConfig())
}

func TestSecuritySchemeMap_WithLoginCommand(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer}}}}`))
	values := openapi.NewEmptySecuritySchemeValues().WithCredentials(auth.NewCredentialRegistry(auth.CredentialOptions{LoginCommand: "echo command-token"}))

	result, err := openapiContract.SecuritySchemeMap(t.Context(), values)

	require.NoError(t, err)
	assert.Equal(t, "Bearer command-token", result["bearer_auth"].GetHeaders().Get("Authorization"))
}

func TestSecuritySchemeMap_ExplicitValueWinsOverCredentials(t *testing.T) {
	openapiContract, _ := openapi.LoadFromData(t.Context(), []byte(`{openapi: 3.0.2, servers: [{url: 'http://localhost:8080'}], paths: {/: {get: {responses: {'204': {description: ok}}, security: [{bearer_auth: []}]}}}, components: {securitySchemes: {bearer_auth: {type: http, scheme: bearer}}}}`))
	token := "explicit"
	values := openapi.NewSecuritySchemeValues(map[string]interface{}{"bearer_auth": &token}).WithCredentials(auth.NewCredentialRegistry(auth.CredentialOptions{LoginCommand: "echo command-token"}))

	result, err := openapiContract.SecuritySchemeMap(t.Context(), values)

	require.NoError(t, err)
	assert.Equal(t, "Bearer explicit", result["bearer_auth"].GetHeaders().Get("Authorization"))
}
