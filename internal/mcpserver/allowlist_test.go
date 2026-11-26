package mcpserver_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cerberauth/vulnapi/internal/mcpserver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowListAllows(t *testing.T) {
	list, err := mcpserver.NewAllowList([]string{"localhost", "127.0.0.1:8080", "*.Example.com", "[::1]"})
	require.NoError(t, err)

	tests := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST:5000", true},
		{"localhost.", true},
		{"127.0.0.1:8080", true},
		{"127.0.0.1:9090", false},
		{"127.0.0.1", false},
		{"api.example.com", true},
		{"a.b.example.com:443", true},
		{"example.com", false},
		{"notexample.com", false},
		{"evil.com", false},
		{"localhost.evil.com", false},
		{"[::1]:3000", true},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			assert.Equal(t, tt.want, list.Allows(tt.host))
		})
	}
}

func TestEmptyAllowListAllowsNothing(t *testing.T) {
	list, err := mcpserver.NewAllowList(nil)
	require.NoError(t, err)
	assert.Equal(t, 0, list.Len())
	assert.False(t, list.Allows("localhost"))
	assert.False(t, (*mcpserver.AllowList)(nil).Allows("localhost"))
}

func TestNewAllowListRejectsInvalidEntries(t *testing.T) {
	for _, entry := range []string{"http://localhost", "localhost/path", "user@host", "*", "*.*.com", "ex*mple.com"} {
		t.Run(entry, func(t *testing.T) {
			_, err := mcpserver.NewAllowList([]string{entry})
			assert.Error(t, err)
		})
	}
}

func TestCheckURL(t *testing.T) {
	list, err := mcpserver.NewAllowList([]string{"localhost"})
	require.NoError(t, err)

	ok, _ := url.Parse("http://localhost:5000/users")
	assert.NoError(t, list.CheckURL(ok))

	other, _ := url.Parse("http://169.254.169.254/latest/meta-data")
	assert.ErrorIs(t, list.CheckURL(other), mcpserver.ErrHostNotAllowed)
	assert.ErrorIs(t, list.CheckURL(&url.URL{Path: "/x"}), mcpserver.ErrHostNotAllowed)
}

func TestListFromHTTPTestServer(t *testing.T) {
	// the loopback address of httptest servers must be matchable by host:port
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer srv.Close()

	list, err := mcpserver.NewAllowList([]string{strings.TrimPrefix(srv.URL, "http://")})
	require.NoError(t, err)
	u, _ := url.Parse(srv.URL)
	assert.NoError(t, list.CheckURL(u))
}
