package scan_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGraphQLScan(t *testing.T) {
	s, err := scan.NewGraphQLScan("http://localhost:8080", http.Header{}, []*http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", s.Operations[0].Request.URL.String())
	assert.Equal(t, "POST", s.Operations[0].Request.Method)
	assert.Equal(t, http.Header{}, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWithHeaders(t *testing.T) {
	header := http.Header{}
	header.Add("Cache-Control", "no-cache")

	s, err := scan.NewGraphQLScan("http://localhost:8080", header, []*http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", s.Operations[0].Request.URL.String())
	assert.Equal(t, "POST", s.Operations[0].Request.Method)
	assert.Equal(t, header, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWithUpperCaseAuthorizationHeader(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "Bearer token")
	token := "token"

	s, err := scan.NewGraphQLScan("http://localhost:8080", header, []*http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", s.Operations[0].Request.URL.String())
	assert.Equal(t, "POST", s.Operations[0].Request.Method)
	assert.Equal(t, header, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWithUpperCaseAuthorizationAndLowerCaseBearerHeader(t *testing.T) {
	header := http.Header{}
	header.Add("Authorization", "bearer token")
	token := "token"

	s, err := scan.NewGraphQLScan("http://localhost:8080", header, []*http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", s.Operations[0].Request.URL.String())
	assert.Equal(t, "POST", s.Operations[0].Request.Method)
	assert.Equal(t, header, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWithLowerCaseAuthorizationHeader(t *testing.T) {
	header := http.Header{}
	header.Add("authorization", "Bearer token")
	token := "token"

	s, err := scan.NewGraphQLScan("http://localhost:8080", header, []*http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", s.Operations[0].Request.URL.String())
	assert.Equal(t, "POST", s.Operations[0].Request.Method)
	assert.Equal(t, header, s.Operations[0].Request.Header)
	assert.Equal(t, []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}
