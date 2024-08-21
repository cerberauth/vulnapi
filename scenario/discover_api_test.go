package scenario_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/vulnapi/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDiscoverScan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	s, err := scenario.NewDiscoverAPIScan(http.MethodGet, server.URL, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
}

func TestNewDiscoverScanWithoutURLProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	url := strings.TrimPrefix(server.URL, "http://")
	s, err := scenario.NewDiscoverAPIScan(http.MethodGet, url, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "https://"+url, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
}

func TestNewDiscoverScanWhenNotReachable(t *testing.T) {
	_, err := scenario.NewDiscoverAPIScan(http.MethodGet, "http://localhost:8009", nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), ":8009: connect: connection refused")
}
