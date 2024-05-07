package scan_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenAPIScanWithHttpBearer(t *testing.T) {
	token := "token"
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	s, err := scan.NewOpenAPIScan(doc, &token, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Operations))
	assert.Equal(t, "http://localhost:8080/", s.Operations[0].Request.URL.String())
	assert.Equal(t, "GET", s.Operations[0].Request.Method)
	assert.Equal(t, http.Header{}, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("bearer_auth", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewOpenAPIScanWithJWTHttpBearer(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer_jwt.openapi.json")
	expectedSecurityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("bearer_auth", &token)
	s, err := scan.NewOpenAPIScan(doc, &token, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, len(s.Operations))
	assert.Equal(t, "http://localhost:8080/", s.Operations[0].Request.URL.String())
	assert.Equal(t, "GET", s.Operations[0].Request.Method)
	assert.Equal(t, http.Header{}, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{expectedSecurityScheme}, s.Operations[0].SecuritySchemes)
}

func TestNewOpenAPIScanWithMultipleOperations(t *testing.T) {
	gofakeit.Seed(1)

	token := "token"
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/basic_http_bearer.openapi.json")
	securitySchemes := []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("bearer_auth", &token)}

	s, err := scan.NewOpenAPIScan(doc, &token, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, len(s.Operations))
	for _, s := range s.Operations {
		assert.Equal(t, s.SecuritySchemes, securitySchemes)
	}
}

func TestNewOpenAPIScanWithoutParamsExample(t *testing.T) {
	gofakeit.Seed(1)

	token := "token"
	doc, _ := openapi.LoadOpenAPI(context.Background(), "../test/stub/basic_http_bearer.openapi.json")
	securitySchemes := []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("bearer_auth", &token)}

	s, err := scan.NewOpenAPIScan(doc, &token, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, len(s.Operations))
	for _, s := range s.Operations {
		assert.Equal(t, s.SecuritySchemes, securitySchemes)
	}
}
