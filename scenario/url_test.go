package scenario_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewURLScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", nil, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewURLScanWithUpperCaseAuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	header := http.Header{}
	token := "token"
	header.Add("Authorization", "Bearer "+token)
	client := request.NewClient(request.NewClientOptions{
		Header: header,
	})

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewURLScanWithUpperCaseAuthorizationAndLowerCaseBearerHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	header := http.Header{}
	token := "token"
	header.Add("Authorization", "bearer "+token)
	client := request.NewClient(request.NewClientOptions{
		Header: header,
	})

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewURLScanWithLowerCaseAuthorizationHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	header := http.Header{}
	token := "token"
	header.Add("authorization", "Bearer "+token)
	client := request.NewClient(request.NewClientOptions{
		Header: header,
	})

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}
