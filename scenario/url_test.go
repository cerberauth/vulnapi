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

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", nil, nil, nil)

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

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
	// Should clear client header after setting security schemes
	assert.Empty(t, client.Header.Get("Authorization"))
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

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil, nil)

	require.NoError(t, err)
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

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)}, s.Operations[0].SecuritySchemes)
}

func TestNewURLScanWithAPIKeyInHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	apiKey := "token"
	tests := []struct {
		name string
	}{
		{
			name: "X-Api-Key",
		},
		{
			name: "Apikey",
		},
		{
			name: "App-Key",
		},
		{
			name: "X-Token",
		},
		{
			name: "Api-Secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			header.Add(tt.name, apiKey)
			client := request.NewClient(request.NewClientOptions{
				Header: header,
			})

			s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil, nil)

			require.NoError(t, err)
			assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAPIKeySecurityScheme(tt.name, auth.InHeader, &apiKey)}, s.Operations[0].SecuritySchemes)
			// Should clear client header after setting security schemes
			assert.Empty(t, client.Header.Get("Authorization"))
		})
	}
}

func TestNewURLScanWithHTTPBasic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	credentials := auth.NewHTTPBasicCredentials("admin", "password")
	header := http.Header{}
	header.Add("Authorization", "Basic YWRtaW46cGFzc3dvcmQ=")
	client := request.NewClient(request.NewClientOptions{
		Header: header,
	})

	s, err := scenario.NewURLScan(http.MethodGet, server.URL, "", client, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, []*auth.SecurityScheme{auth.MustNewAuthorizationBasicSecurityScheme("default", credentials)}, s.Operations[0].SecuritySchemes)
	// Should clear client header after setting security schemes
	assert.Empty(t, client.Header.Get("Authorization"))
}
