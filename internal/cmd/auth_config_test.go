package cmd_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const authConfig = `version: 1
auth:
  clientId: { env: VULNAPI_TEST_FILE_CLIENT_ID }
  clientSecret: { file: client-secret }
  tokenUrl: https://auth.example.com/token
  scopes: [read, write]
environments:
  login:
    auth:
      clientId: { env: VULNAPI_TEST_FILE_CLIENT_ID }
      login:
        url: https://api.example.com/login
        data: { env: VULNAPI_TEST_LOGIN_BODY }
        tokenField: data.token
`

func newAuthCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	t.Cleanup(cmd.ClearValues)
	c := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
	cmd.AddConfigFlags(c.Flags())
	cmd.AddCommonArgs(c)
	cmd.AddAuthFlags(c)
	require.NoError(t, c.ParseFlags(args))
	c.SetContext(t.Context())
	return c
}

func applyAuth(t *testing.T, c *cobra.Command) (*cmd.ScanSettings, error) {
	t.Helper()
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)
	_, err = cmd.ApplyAuthFlags(c, request.GetDefaultClient(), settings)
	return settings, err
}

func TestApplyAuthFlags_FromConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "vulnapi.yaml", authConfig)
	writeConfig(t, dir, "client-secret", "file-secret\n")
	t.Setenv("VULNAPI_TEST_FILE_CLIENT_ID", "file-client")

	c := newAuthCmd(t, "--config", path)
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)
	registry, err := cmd.ApplyAuthFlags(c, request.GetDefaultClient(), settings)
	require.NoError(t, err)

	options := registry.Options()
	assert.Equal(t, "file-client", options.ClientID)
	assert.Equal(t, "file-secret", options.ClientSecret)
	assert.Equal(t, "https://auth.example.com/token", options.TokenURL)
	assert.Equal(t, []string{"read", "write"}, options.Scopes)
}

func TestApplyAuthFlags_FlagsAndEnvOverrideFile(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "vulnapi.yaml", authConfig)
	writeConfig(t, dir, "client-secret", "file-secret")
	t.Setenv("VULNAPI_TEST_FILE_CLIENT_ID", "file-client")
	t.Setenv(cmd.ClientSecretEnv, "env-secret")

	c := newAuthCmd(t, "--config", path, "--client-id", "flag-client", "--token-url", "https://other.example.com/token", "--oauth2-scope", "admin")
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)
	registry, err := cmd.ApplyAuthFlags(c, request.GetDefaultClient(), settings)
	require.NoError(t, err)

	options := registry.Options()
	assert.Equal(t, "flag-client", options.ClientID)
	assert.Equal(t, "env-secret", options.ClientSecret)
	assert.Equal(t, "https://other.example.com/token", options.TokenURL)
	assert.Equal(t, []string{"admin"}, options.Scopes)
}

func TestApplyAuthFlags_LoginFromEnvironmentOverlay(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, "vulnapi.yaml", authConfig)
	writeConfig(t, dir, "client-secret", "file-secret")
	t.Setenv("VULNAPI_TEST_FILE_CLIENT_ID", "file-client")
	t.Setenv("VULNAPI_TEST_LOGIN_BODY", `{"user":"alice"}`)

	c := newAuthCmd(t, "--config", path, "--env", "login")
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)
	registry, err := cmd.ApplyAuthFlags(c, request.GetDefaultClient(), settings)
	require.NoError(t, err)

	options := registry.Options()
	assert.Equal(t, "https://api.example.com/login", options.LoginURL)
	assert.Equal(t, `{"user":"alice"}`, options.LoginData)
	assert.Equal(t, "data.token", options.LoginTokenField)
	assert.True(t, registry.HasLogin())

	c = newAuthCmd(t, "--config", path, "--env", "login", "--login-command", "echo token")
	settings, err = cmd.ResolveScanSettings(c)
	require.NoError(t, err)
	registry, err = cmd.ApplyAuthFlags(c, request.GetDefaultClient(), settings)
	require.NoError(t, err)
	assert.Equal(t, "echo token", registry.Options().LoginCommand)
	assert.Empty(t, registry.Options().LoginURL)
}

func TestApplyAuthFlags_UnresolvableSecret(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "vulnapi.yaml", authConfig)

	_, err := applyAuth(t, newAuthCmd(t, "--config", path))

	assert.ErrorContains(t, err, "auth.clientId: environment variable VULNAPI_TEST_FILE_CLIENT_ID is not set")
}
