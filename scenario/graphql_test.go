package scenario_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGraphQLScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	s, err := scenario.NewGraphQLScan(server.URL, nil, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodPost, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWithoutURLProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	url := strings.TrimPrefix(server.URL, "http://")
	s, err := scenario.NewGraphQLScan(url, nil, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "https://"+url, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodPost, s.Operations[0].Method)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWhenNotReachable(t *testing.T) {
	_, err := scenario.NewGraphQLScan("http://localhost:8009", nil, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), ":8009: connect: connection refused")
}

func TestNewGraphQLScanWithUpperCaseAuthorizationHeader(t *testing.T) {
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

	s, err := scenario.NewGraphQLScan(server.URL, client, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
	// Should clear client header after setting security schemes
	assert.Empty(t, client.Header.Get("Authorization"))
}

func TestNewGraphQLScanWithUpperCaseAuthorizationAndLowerCaseBearerHeader(t *testing.T) {
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

	s, err := scenario.NewGraphQLScan(server.URL, client, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewGraphQLScanWithLowerCaseAuthorizationHeader(t *testing.T) {
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

	s, err := scenario.NewGraphQLScan(server.URL, client, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}
