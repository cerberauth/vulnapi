package cmd_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/vulnapi/config"
	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const settingsConfig = `version: 1
scan:
  checks:
    include: [jwt]
    exclude: [jwt.fuzz]
  operations:
    excludePaths: ["/internal/**"]
  allowUnsafeMethods: true
  rate: 5/s
  timeout: 1500ms
report:
  failOn: high
environments:
  production:
    scan:
      allowUnsafeMethods: false
    report:
      failOn: medium
`

func writeConfig(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func newSettingsCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	t.Cleanup(cmd.ClearValues)
	c := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
	cmd.AddConfigFlags(c.Flags())
	cmd.AddCommonArgs(c)
	require.NoError(t, c.ParseFlags(args))
	return c
}

func TestResolveScanSettings_NoConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	settings, err := cmd.ResolveScanSettings(newSettingsCmd(t, "--scans", "jwt.alg_none"))
	require.NoError(t, err)

	assert.Nil(t, settings.Config)
	assert.Equal(t, []string{"jwt.alg_none"}, settings.IncludeScans)
	assert.Equal(t, float64(1), settings.SeverityThreshold)
	assert.Nil(t, settings.Operations)
}

func TestResolveScanSettings_FileOnly(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "custom.yaml", settingsConfig)
	c := newSettingsCmd(t, "--config", path)
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)

	assert.Equal(t, []string{"jwt"}, settings.IncludeScans)
	assert.Equal(t, []string{"jwt.fuzz"}, settings.ExcludeScans)
	assert.True(t, settings.ScansFromConfig)
	assert.True(t, settings.AllowUnsafeMethods)
	assert.Equal(t, float64(7), settings.SeverityThreshold)
	assert.Equal(t, float64(7), cmd.GetSeverityThreshold())
	assert.Equal(t, []string{"/internal/**"}, settings.Operations.ExcludePaths)
	assert.False(t, settings.ScansFiltered(c))
	assert.True(t, settings.ScanOptions().SkipUnknownScans)

	rate, _ := c.Flags().GetString("rate")
	assert.Equal(t, "5/s", rate)
	maxTime, _ := c.Flags().GetFloat64("max-time")
	assert.Equal(t, 1.5, maxTime)
}

func TestResolveScanSettings_FlagsOverrideFile(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "custom.yaml", settingsConfig)
	c := newSettingsCmd(t, "--config", path, "--scans", "misconfiguration", "--exclude-scans", "misconfiguration.http_trace", "--allow-unsafe-methods=false", "--severity-threshold", "3", "--rate", "1/s")
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)

	assert.Equal(t, []string{"misconfiguration"}, settings.IncludeScans)
	assert.Equal(t, []string{"misconfiguration.http_trace"}, settings.ExcludeScans)
	assert.False(t, settings.ScansFromConfig)
	assert.False(t, settings.AllowUnsafeMethods)
	assert.Equal(t, float64(3), settings.SeverityThreshold)
	assert.True(t, settings.ScansFiltered(c))
	rate, _ := c.Flags().GetString("rate")
	assert.Equal(t, "1/s", rate)
}

func TestResolveScanSettings_EnvironmentOverlay(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "custom.yaml", settingsConfig)
	t.Setenv(config.PathEnv, path)
	t.Setenv(config.EnvironmentEnv, "production")
	settings, err := cmd.ResolveScanSettings(newSettingsCmd(t))
	require.NoError(t, err)

	assert.Equal(t, "production", settings.Config.EnvironmentName())
	assert.False(t, settings.AllowUnsafeMethods)
	assert.Equal(t, float64(4), settings.SeverityThreshold)
	assert.Equal(t, []string{"jwt"}, settings.IncludeScans)

	_, err = cmd.ResolveScanSettings(newSettingsCmd(t, "--env", "staging"))
	assert.ErrorContains(t, err, `environment "staging" not found`)
}

func TestResolveScanSettings_DiscoversFile(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir, ".vulnapi.yaml", settingsConfig)
	t.Chdir(dir)
	settings, err := cmd.ResolveScanSettings(newSettingsCmd(t))
	require.NoError(t, err)

	require.NotNil(t, settings.Config)
	assert.Equal(t, filepath.Join(dir, ".vulnapi.yaml"), settings.Config.Path())
}

func TestResolveScanSettings_InvalidFile(t *testing.T) {
	path := writeConfig(t, t.TempDir(), "custom.yaml", "version: 1\nscan:\n  rates: 5/s\n")
	_, err := cmd.ResolveScanSettings(newSettingsCmd(t, "--config", path))
	assert.ErrorContains(t, err, "field rates not found")
}

func TestResolveScanSettings_EnvWithoutFile(t *testing.T) {
	t.Chdir(t.TempDir())
	_, err := cmd.ResolveScanSettings(newSettingsCmd(t, "--env", "production"))
	assert.ErrorContains(t, err, "--env requires a configuration file")
}
