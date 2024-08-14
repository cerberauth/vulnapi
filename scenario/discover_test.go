package scenario_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiscoverScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	s, err := scenario.NewDiscoverScan(http.MethodGet, server.URL, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].Request.URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Request.Method)
	assert.Equal(t, []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewDiscoverScanWithoutURLProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	url := strings.TrimPrefix(server.URL, "http://")
	s, err := scenario.NewDiscoverScan(http.MethodGet, url, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "https://"+url, s.Operations[0].Request.URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Request.Method)
	assert.Equal(t, []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}, s.Operations[0].SecuritySchemes)
}

func TestNewDiscoverScanWhenNotReachable(t *testing.T) {
	_, err := scenario.NewDiscoverScan(http.MethodGet, "http://localhost:8009", nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), ":8009: connect: connection refused")
}
