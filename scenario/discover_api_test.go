package scenario_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
	u, _ := url.Parse(server.URL)

	s, err := scenario.NewDiscoverAPIScan(http.MethodGet, u, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, server.URL, s.Operations[0].URL.String())
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
}

func TestNewDiscoverScanWithoutURLProto(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	u.Scheme = ""

	s, err := scenario.NewDiscoverAPIScan(http.MethodGet, u, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "http", s.Operations[0].URL.Scheme)
	assert.Equal(t, http.MethodGet, s.Operations[0].Method)
}

func TestNewDiscoverScanWhenNotReachable(t *testing.T) {
	u, _ := url.Parse("http://localhost:8009")

	_, err := scenario.NewDiscoverAPIScan(http.MethodGet, u, nil, nil)

	require.Error(t, err)
	assert.Contains(t, err.Error(), ":8009: connect: connection refused")
}
