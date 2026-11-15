package config_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/vulnapi/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretRef_Resolve(t *testing.T) {
	t.Setenv("VULNAPI_TEST_SECRET", "from-env")
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "token"), []byte("from-file\n"), 0o600))

	data := []byte(`version: 1
identities:
  user:
    schemes:
      env: { env: VULNAPI_TEST_SECRET }
      file: { file: token }
      command: { command: echo from-command }
`)
	c, err := config.Parse(data, dir)
	require.NoError(t, err)

	schemes := c.Identities["user"].Schemes
	for name, want := range map[string]string{"env": "from-env", "file": "from-file", "command": "from-command"} {
		got, err := schemes[name].Resolve(t.Context(), nil, "")
		require.NoError(t, err, name)
		assert.Equal(t, want, got, name)
	}
}

func TestSecretRef_ResolveUnsetEnv(t *testing.T) {
	_, err := config.SecretRef{Env: "VULNAPI_TEST_UNSET"}.Resolve(t.Context())
	assert.ErrorContains(t, err, "environment variable VULNAPI_TEST_UNSET is not set")
}

func TestSecretRef_ExactlyOneSource(t *testing.T) {
	_, err := config.Parse([]byte(`version: 1
identities:
  user:
    schemes:
      bearerAuth: { env: A, file: b }
`), t.TempDir())
	assert.ErrorContains(t, err, "identities.user.schemes.bearerAuth: exactly one of env, file or command is required")
}

func TestValue_LiteralOrReference(t *testing.T) {
	t.Setenv("VULNAPI_TEST_HEADER", "secret")
	c, err := config.Parse([]byte(`version: 1
report:
  url: https://reports.example.com
  headers:
    X-Team: api
    Authorization: { env: VULNAPI_TEST_HEADER }
`), t.TempDir())
	require.NoError(t, err)

	team, err := c.Report.Headers["X-Team"].Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "api", team)
	authorization, err := c.Report.Headers["Authorization"].Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "secret", authorization)

	out, err := c.MarshalMaskedYAML()
	require.NoError(t, err)
	assert.Contains(t, string(out), "X-Team: '****'")
	assert.Contains(t, string(out), "env: VULNAPI_TEST_HEADER")
}

func TestCredential_ResolveOAuth2(t *testing.T) {
	t.Setenv("VULNAPI_TEST_CLIENT_ID", "client")
	t.Setenv("VULNAPI_TEST_CLIENT_SECRET", "secret")
	t.Setenv("VULNAPI_TEST_USERNAME", "alice")
	t.Setenv("VULNAPI_TEST_PASSWORD", "wonderland")
	var grants []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		grants = append(grants, r.Form.Get("grant_type"))
		if r.Form.Get("grant_type") == "password" && (r.Form.Get("username") != "alice" || r.Form.Get("password") != "wonderland") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"token-` + r.Form.Get("grant_type") + `","token_type":"bearer","expires_in":3600}`))
	}))
	defer server.Close()

	c, err := config.Parse([]byte(`version: 1
identities:
  user:
    schemes:
      clientCredentials:
        oauth2: { clientId: { env: VULNAPI_TEST_CLIENT_ID }, clientSecret: { env: VULNAPI_TEST_CLIENT_SECRET }, scopes: [read] }
      password:
        oauth2:
          tokenUrl: `+server.URL+`
          clientId: { env: VULNAPI_TEST_CLIENT_ID }
          username: { env: VULNAPI_TEST_USERNAME }
          password: { env: VULNAPI_TEST_PASSWORD }
`), t.TempDir())
	require.NoError(t, err)
	schemes := c.Identities["user"].Schemes

	_, err = schemes["clientCredentials"].Resolve(t.Context(), nil, "")
	assert.ErrorContains(t, err, "tokenUrl is required")

	token, err := schemes["clientCredentials"].Resolve(t.Context(), server.Client(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, "token-client_credentials", token)

	token, err = schemes["password"].Resolve(t.Context(), server.Client(), "")
	require.NoError(t, err)
	assert.Equal(t, "token-password", token)
	assert.Equal(t, []string{"client_credentials", "password"}, grants)
}
