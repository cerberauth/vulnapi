package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/vulnapi/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_FileOnly(t *testing.T) {
	c, err := config.Load("testdata/full.yaml")
	require.NoError(t, err)

	dir, _ := filepath.Abs("testdata")
	assert.Equal(t, 1, c.Version)
	assert.Equal(t, "openapi", c.TargetKind())
	assert.Equal(t, filepath.Join(dir, "openapi.yaml"), c.Target.OpenAPI)
	assert.Equal(t, "https://staging.api.example.com", c.Target.Server)
	assert.Equal(t, "USER_TOKEN", c.Identities["user"].Schemes["bearerAuth"].Env)
	assert.Equal(t, "admin", c.Identities["admin"].Role)
	assert.Equal(t, "ADMIN_ID", c.Identities["admin"].Schemes["bearerAuth"].OAuth2.ClientID.Env)
	assert.Equal(t, []string{"misconfiguration.http_headers_cors_missing"}, c.Scan.Checks.Exclude)
	assert.Equal(t, []string{"/internal/**"}, c.Scan.Operations.ExcludePaths)
	assert.False(t, *c.Scan.AllowUnsafeMethods)
	assert.Equal(t, "10/s", c.Scan.Rate)
	assert.Equal(t, "high", c.Report.FailOn)
	assert.Equal(t, filepath.Join(dir, "vulnapi.sarif"), c.Report.Outputs[0].Path)
	assert.Equal(t, "2027-03-01", c.Suppressions[0].Expires.Format(config.DateLayout))
	assert.True(t, c.HasEnterprise())
}

func TestWithEnvironment_Overlay(t *testing.T) {
	c, err := config.Load("testdata/full.yaml")
	require.NoError(t, err)

	production, err := c.WithEnvironment("production")
	require.NoError(t, err)

	assert.Equal(t, "production", production.EnvironmentName())
	assert.Equal(t, "https://api.example.com", production.Target.Server)
	assert.Equal(t, c.Target.OpenAPI, production.Target.OpenAPI)
	assert.Equal(t, "2/s", production.Scan.Rate)
	assert.Equal(t, c.Scan.Checks, production.Scan.Checks)
	assert.Equal(t, "https://staging.api.example.com", c.Target.Server)

	_, err = c.WithEnvironment("staging")
	assert.ErrorContains(t, err, `environment "staging" not found, available: production`)
}

func TestLoad_Rejected(t *testing.T) {
	tests := []struct {
		file string
		want []string
	}{
		{file: "unknown-key.yaml", want: []string{"field ratelimit not found"}},
		{file: "literal-secret.yaml", want: []string{"identities.user.schemes.bearerAuth: secrets must be a reference"}},
		{file: "missing-version.yaml", want: []string{"version: required"}},
		{file: "invalid.yaml", want: []string{
			"target: set only one of openapi, graphql or request",
			`target.graphql: "not-a-url" is not an absolute URL`,
			"identities.user.schemes.bearerAuth.oauth2: username and password must be set together",
			`scan.operations.methods: unknown HTTP method "FETCH"`,
			`scan.timeout: invalid duration "soon"`,
			`scan.rate: invalid rate "fast"`,
			`report.failOn: invalid failOn "severe"`,
			`report.outputs[0].format: unknown format "docx"`,
			"suppressions[0].reason: required",
			"suppressions[0].expires: required",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			_, err := config.Load(filepath.Join("testdata", tt.file))
			require.Error(t, err)
			for _, want := range tt.want {
				assert.ErrorContains(t, err, want)
			}
		})
	}
}

func TestLoad_LiteralSecretIsNotEchoed(t *testing.T) {
	_, err := config.Load("testdata/literal-secret.yaml")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "eyJhbGciOiJIUzI1NiJ9")
}

func TestLoad_EnterpriseBlockIsIgnored(t *testing.T) {
	data, err := os.ReadFile("testdata/full.yaml")
	require.NoError(t, err)
	withEnterprise, err := config.Parse(data, "testdata")
	require.NoError(t, err)
	without, err := config.Parse(data[:bytes.Index(data, []byte("enterprise:"))], "testdata")
	require.NoError(t, err)

	assert.True(t, withEnterprise.HasEnterprise())
	assert.False(t, without.HasEnterprise())
	withEnterprise.Enterprise = without.Enterprise
	assert.Equal(t, without, withEnterprise)
}

func TestDiscover(t *testing.T) {
	dir := t.TempDir()
	path, err := config.Discover(dir)
	require.NoError(t, err)
	assert.Empty(t, path)

	require.NoError(t, os.WriteFile(filepath.Join(dir, ".vulnapi.yaml"), []byte("version: 1\n"), 0o600))
	path, err = config.Discover(dir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, ".vulnapi.yaml"), path)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "vulnapi.yaml"), []byte("version: 1\n"), 0o600))
	path, err = config.Discover(dir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "vulnapi.yaml"), path)
}

func TestParseFailOn(t *testing.T) {
	for value, want := range map[string]float64{"info": 0, "low": 0.1, "Medium": 4, "high": 7, "critical": 9, "6.5": 6.5} {
		got, err := config.ParseFailOn(value)
		require.NoError(t, err)
		assert.Equal(t, want, got, value)
	}
	_, err := config.ParseFailOn("11")
	assert.Error(t, err)
}

func TestLoad_Auth(t *testing.T) {
	c, err := config.Parse([]byte(`version: 1
auth:
  clientId: { env: CLIENT_ID }
  clientSecret: { file: secrets/client }
  jwtPublicKey: keys/public.pem
  login:
    command: ./login.sh
environments:
  production:
    auth:
      tokenUrl: https://auth.example.com/token
`), "/etc/vulnapi")
	require.NoError(t, err)
	assert.Equal(t, "/etc/vulnapi/secrets/client", c.Auth.ClientSecret.File)
	assert.Equal(t, "/etc/vulnapi/keys/public.pem", c.Auth.JWTPublicKey)

	production, err := c.WithEnvironment("production")
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/token", production.Auth.TokenURL)
	assert.Equal(t, "CLIENT_ID", production.Auth.ClientID.Env)
	assert.Equal(t, "./login.sh", production.Auth.Login.Command)
}

func TestLoad_AuthRejected(t *testing.T) {
	_, err := config.Parse([]byte(`version: 1
auth:
  clientSecret: s3cr3t
  username: { env: USER }
  login:
    command: ./login.sh
    url: https://api.example.com/login
    data: '{"password":"s3cr3t"}'
`), t.TempDir())
	require.Error(t, err)
	for _, want := range []string{
		"auth.clientSecret: secrets must be a reference",
		"auth.clientId: required for the OAuth2 flows",
		"auth: username and password must be set together",
		"auth.login: set exactly one of command or url",
		"auth.login.data: secrets must be a reference",
	} {
		assert.ErrorContains(t, err, want)
	}
	assert.NotContains(t, err.Error(), "s3cr3t")
}
