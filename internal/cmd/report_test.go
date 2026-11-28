package cmd_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReportCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	c := &cobra.Command{Use: "test", Run: func(*cobra.Command, []string) {}}
	cmd.AddCommonArgs(c)
	require.NoError(t, c.ParseFlags(args))
	return c
}

func newReport(t *testing.T) *reportx.Report {
	t.Helper()
	r, err := reportx.NewBuilder().
		Tool("vulnapi", "test").
		Target("http://localhost:8080").
		Findings([]reportx.Finding{{
			ID:       "jwt.alg_none",
			Title:    "JWT Algorithm None",
			Severity: reportx.SeverityHigh,
			Status:   reportx.StatusActive,
		}}).
		Build(context.Background())
	require.NoError(t, err)
	return r
}

func TestWriteReport_OutputFileUsesOutputFormat(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	c := newReportCmd(t, "--quiet", "--output", output, "--output-format", "json")

	require.NoError(t, cmd.WriteReport(context.Background(), c, newReport(t), nil))

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	var report struct {
		Findings []struct {
			Title string `json:"title"`
		} `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(content, &report), "the --output file must be JSON, not the terminal report")
	require.Len(t, report.Findings, 1)
	assert.Equal(t, "JWT Algorithm None", report.Findings[0].Title)
}

func TestWriteReport_OutputFileSarif(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.sarif.json")
	c := newReportCmd(t, "--quiet", "--output", output, "--output-format", "sarif")

	require.NoError(t, cmd.WriteReport(context.Background(), c, newReport(t), nil))

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	var sarif struct {
		Version string `json:"version"`
	}
	require.NoError(t, json.Unmarshal(content, &sarif))
	assert.Equal(t, "2.1.0", sarif.Version)
}

func TestWriteReport_KeepsTerminalReportOnStdoutWithOutputFile(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	c := newReportCmd(t, "--no-color", "--output", output, "--output-format", "json")

	stdout := captureStdout(t, func() {
		require.NoError(t, cmd.WriteReport(context.Background(), c, newReport(t), nil))
	})

	assert.Contains(t, stdout, "JWT Algorithm None")
	content, err := os.ReadFile(output)
	require.NoError(t, err)
	assert.True(t, json.Valid(content))
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = stdout }()

	fn()

	require.NoError(t, w.Close())
	content, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(content)
}

func TestWriteReport_StdoutIsOnlyTheReport(t *testing.T) {
	c := newReportCmd(t, "--format", "json")

	stdout := captureStdout(t, func() {
		require.NoError(t, cmd.WriteReport(context.Background(), c, newReport(t), nil))
	})

	assert.True(t, json.Valid([]byte(stdout)), "stdout must be a single JSON document, got: %q", stdout)
}
