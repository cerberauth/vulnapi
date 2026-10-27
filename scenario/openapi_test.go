package scenario_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadOpenAPIWithTestServer loads the OpenAPI document at path and points
// its base URL at a test server, so tests don't depend on a fixed port.
func loadOpenAPIWithTestServer(t *testing.T, path string) (*openapi.OpenAPI, *url.URL) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	doc, err := openapi.LoadOpenAPI(t.Context(), path)
	require.NoError(t, err)

	baseUrl, err := url.Parse(server.URL + "/")
	require.NoError(t, err)
	doc.SetBaseUrl(baseUrl)

	return doc, baseUrl
}

func TestNewOpenAPIScanWithHttpBearer(t *testing.T) {
	token := "token"
	doc, baseUrl := loadOpenAPIWithTestServer(t, "../test/stub/simple_http_bearer.openapi.json")
	securitySchemeValues := openapi.NewSecuritySchemeValues(map[string]interface{}{
		"bearer_auth": &token,
	})

	s, err := scenario.NewOpenAPIScan(t.Context(), harnessx.New(), doc, securitySchemeValues, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Operations))
	assert.Equal(t, baseUrl.String(), s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("bearer_auth", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewOpenAPIScanWithJWTHttpBearer(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	doc, baseUrl := loadOpenAPIWithTestServer(t, "../test/stub/simple_http_bearer_jwt.openapi.json")
	expectedSecurityScheme := auth.MustNewAuthorizationBearerSecurityScheme("bearer_auth", &token)
	securitySchemeValues := openapi.NewSecuritySchemeValues(map[string]interface{}{
		"bearer_auth": &token,
	})

	s, err := scenario.NewOpenAPIScan(t.Context(), harnessx.New(), doc, securitySchemeValues, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Operations))
	assert.Equal(t, baseUrl.String(), s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{expectedSecurityScheme}, s.Operations[0].SecuritySchemes)
}

func TestNewOpenAPIScanWithMultipleOperations(t *testing.T) {
	gofakeit.Seed(1)

	token := "token"
	doc, _ := loadOpenAPIWithTestServer(t, "../test/stub/basic_http_bearer.openapi.json")
	securitySchemes := []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("bearer_auth", &token)}
	securitySchemeValues := openapi.NewSecuritySchemeValues(map[string]interface{}{
		"bearer_auth": &token,
	})

	s, err := scenario.NewOpenAPIScan(t.Context(), harnessx.New(), doc, securitySchemeValues, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, len(s.Operations))
	for _, s := range s.Operations {
		assert.Equal(t, s.SecuritySchemes, securitySchemes)
	}
}

func TestNewOpenAPIScanWithoutParamsExample(t *testing.T) {
	gofakeit.Seed(1)

	token := "token"
	doc, _ := loadOpenAPIWithTestServer(t, "../test/stub/basic_http_bearer.openapi.json")
	securitySchemes := []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("bearer_auth", &token)}
	securitySchemeValues := openapi.NewSecuritySchemeValues(map[string]interface{}{
		"bearer_auth": &token,
	})

	s, err := scenario.NewOpenAPIScan(t.Context(), harnessx.New(), doc, securitySchemeValues, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, len(s.Operations))
	for _, s := range s.Operations {
		assert.Equal(t, s.SecuritySchemes, securitySchemes)
	}
}

func TestNewOpenAPIScanWithoutOperations(t *testing.T) {
	doc, _ := loadOpenAPIWithTestServer(t, "../test/stub/simple_http_bearer.openapi.json")
	doc.Doc.Paths = openapi3.NewPaths()

	s, err := scenario.NewOpenAPIScan(t.Context(), harnessx.New(), doc, openapi.NewSecuritySchemeValues(nil), nil, nil)

	assert.Nil(t, s)
	assert.EqualError(t, err, "no operations found in the OpenAPI document")
}
