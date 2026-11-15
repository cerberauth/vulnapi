package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	configcmd "github.com/cerberauth/vulnapi/cmd/config"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "vulnapi"}
	internalCmd.AddConfigFlags(root.PersistentFlags())
	root.AddCommand(configcmd.NewConfigCmd())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestConfigValidateAndShow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vulnapi.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`version: 1
target:
  graphql: https://api.example.com/graphql
  headers:
    X-Api-Version: "2"
    Authorization: { env: API_TOKEN }
scan:
  rate: 10/s
environments:
  production:
    scan: { rate: 2/s }
`), 0o600))

	out, err := run(t, "config", "validate", "--config", path, "--env", "production")
	require.NoError(t, err)
	assert.Contains(t, out, path+" is valid (environment production)")

	out, err = run(t, "config", "show", "--config", path, "--env", "production")
	require.NoError(t, err)
	assert.Contains(t, out, "rate: 2/s")
	assert.Contains(t, out, "env: API_TOKEN")
	assert.Contains(t, out, "X-Api-Version: '****'")
	assert.NotContains(t, out, "environments:")

	t.Chdir(t.TempDir())
	_, err = run(t, "config", "validate")
	assert.ErrorContains(t, err, "no configuration file found")
}
