package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tokenEndpoint struct {
	URL       string
	issued    atomic.Int32
	expiresIn int
}

func newTokenEndpoint(t *testing.T, expiresIn int) *tokenEndpoint {
	t.Helper()
	endpoint := &tokenEndpoint{expiresIn: expiresIn}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok {
			clientID, clientSecret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if clientID != "client" || clientSecret != "s3cr3t" || (r.PostForm.Get("grant_type") == "password" && r.PostForm.Get("password") != "pass") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"bad s3cr3t"}`))
			return
		}
		n := endpoint.issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   endpoint.expiresIn,
		})
	}))
	t.Cleanup(srv.Close)
	endpoint.URL = srv.URL
	return endpoint
}

func TestOAuth2ClientCredentials_FetchesAndCaches(t *testing.T) {
	endpoint := newTokenEndpoint(t, 3600)
	credential := auth.NewManagedCredential(auth.NewOAuth2ClientCredentialsSource(endpoint.URL, "client", "s3cr3t", nil, nil))

	first, err := credential.Value(context.Background())
	require.NoError(t, err)
	second, err := credential.Value(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "token-1", first)
	assert.Equal(t, first, second)
	assert.Equal(t, int32(1), endpoint.issued.Load())
}

func TestOAuth2ClientCredentials_RefreshesExpiredToken(t *testing.T) {
	endpoint := newTokenEndpoint(t, 1)
	credential := auth.NewManagedCredential(auth.NewOAuth2ClientCredentialsSource(endpoint.URL, "client", "s3cr3t", nil, nil))

	first, err := credential.Value(context.Background())
	require.NoError(t, err)
	second, err := credential.Value(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "token-1", first)
	assert.Equal(t, "token-2", second)
}

func TestOAuth2ClientCredentials_WrongCredentials(t *testing.T) {
	endpoint := newTokenEndpoint(t, 3600)
	credential := auth.NewManagedCredential(auth.NewOAuth2ClientCredentialsSource(endpoint.URL, "client", "wrong", nil, nil))

	_, err := credential.Value(context.Background())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 401")
	assert.Contains(t, err.Error(), "invalid_client")
	assert.NotContains(t, err.Error(), "s3cr3t")
	assert.NotContains(t, err.Error(), "wrong")
}

func TestOAuth2Password(t *testing.T) {
	endpoint := newTokenEndpoint(t, 3600)
	credential := auth.NewManagedCredential(auth.NewOAuth2PasswordSource(endpoint.URL, "client", "s3cr3t", "user", "pass", nil, nil))

	value, err := credential.Value(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "token-1", value)
}

func TestCommandSource(t *testing.T) {
	credential := auth.NewManagedCredential(auth.NewCommandSource("echo  token-from-command "))

	value, err := credential.Value(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "token-from-command", value)
}

func TestCommandSource_Failure(t *testing.T) {
	credential := auth.NewManagedCredential(auth.NewCommandSource("echo secret-output; exit 3"))

	_, err := credential.Value(context.Background())

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "secret-output")
}

func TestHTTPLoginSource(t *testing.T) {
	var gotBody, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody, gotContentType = string(body), r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{"data":{"token":"login-token"},"expires_in":60}`))
	}))
	defer srv.Close()
	credential := auth.NewManagedCredential(auth.NewHTTPLoginSource(srv.URL, `{"user":"u","password":"p"}`, "data.token", nil))

	value, err := credential.Value(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "login-token", value)
	assert.Equal(t, `{"user":"u","password":"p"}`, gotBody)
	assert.Equal(t, "application/json", gotContentType)
}

func TestHTTPLoginSource_MissingField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token":"x"}`))
	}))
	defer srv.Close()
	credential := auth.NewManagedCredential(auth.NewHTTPLoginSource(srv.URL, "", "", nil))

	_, err := credential.Value(context.Background())

	assert.ErrorContains(t, err, `no "access_token" field`)
}

func TestRefreshTransport_RetriesOnceAfter401(t *testing.T) {
	endpoint := newTokenEndpoint(t, 3600)
	registry := auth.NewCredentialRegistry(auth.CredentialOptions{ClientID: "client", ClientSecret: "s3cr3t", TokenURL: endpoint.URL})
	credential := registry.Default()
	stale, err := credential.Value(context.Background())
	require.NoError(t, err)

	var seen []string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer token-2" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer api.Close()
	client := &http.Client{Transport: registry.Transport(http.DefaultTransport)}

	req, _ := http.NewRequest(http.MethodPost, api.URL, strings.NewReader("body"))
	req.Header.Set("Authorization", "Bearer "+stale)
	resp, err := client.Do(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"Bearer token-1", "Bearer token-2"}, seen)

	req, _ = http.NewRequest(http.MethodGet, api.URL, nil)
	req.Header.Set("Authorization", "Bearer attack-token")
	resp, err = client.Do(req)

	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, int32(2), endpoint.issued.Load())
}

func TestSecurityScheme_SetCredential(t *testing.T) {
	endpoint := newTokenEndpoint(t, 3600)
	credential := auth.NewManagedCredential(auth.NewOAuth2ClientCredentialsSource(endpoint.URL, "client", "s3cr3t", nil, nil))
	securityScheme := auth.MustNewOAuthSecurityScheme("oauth", nil, nil, nil)

	require.NoError(t, securityScheme.SetCredential(context.Background(), credential))

	assert.True(t, securityScheme.HasValidValue())
	assert.Equal(t, "token-1", securityScheme.GetToken())
	assert.Equal(t, "Bearer token-1", securityScheme.GetHeaders().Get("Authorization"))
}

func TestSecurityScheme_SetCredential_Failure(t *testing.T) {
	endpoint := newTokenEndpoint(t, 3600)
	credential := auth.NewManagedCredential(auth.NewOAuth2ClientCredentialsSource(endpoint.URL, "client", "wrong", nil, nil))
	securityScheme := auth.MustNewOAuthSecurityScheme("oauth", nil, nil, nil)

	err := securityScheme.SetCredential(context.Background(), credential)

	assert.ErrorContains(t, err, `obtaining credentials for security scheme "oauth"`)
	assert.False(t, securityScheme.HasValidValue())
}
