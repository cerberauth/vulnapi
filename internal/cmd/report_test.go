package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/reportx"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReportCmd(t *testing.T, args ...string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "test"}
	cobrareportx.RegisterFormatFlags(cmd)
	cobrareportx.RegisterTransportFlags(cmd)
	require.NoError(t, cmd.ParseFlags(args))
	return cmd
}

func newReport(t *testing.T, scores ...float64) *reportx.Report {
	t.Helper()
	findings := make([]reportx.Finding, len(scores))
	for i, score := range scores {
		findings[i] = reportx.Finding{ID: "check", Title: "Check", CVSS40Score: score, Severity: reportx.SeverityHigh}
	}
	r, err := reportx.NewBuilder().Title("Test").Tool("vulnapi", "test").Target("http://localhost:8080").Findings(findings).Build(t.Context())
	require.NoError(t, err)
	return r
}

type jsonReport struct {
	Findings []struct {
		ID string `json:"id"`
	} `json:"findings"`
}

func TestHighestCVSSScore(t *testing.T) {
	assert.Equal(t, 0.0, highestCVSSScore(newReport(t)))
	assert.Equal(t, 9.3, highestCVSSScore(newReport(t, 5.1, 9.3, 0)))
}

func TestWriteReportToOutputFile(t *testing.T) {
	output := filepath.Join(t.TempDir(), "report.json")
	cmd := newReportCmd(t, "--format", "json", "--output", output)

	err := WriteReport(t.Context(), cmd, newReport(t, 5.1))

	require.NoError(t, err)
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	var r jsonReport
	require.NoError(t, json.Unmarshal(data, &r))
	require.Len(t, r.Findings, 1)
	assert.Equal(t, "check", r.Findings[0].ID)
}

func TestWriteReportSendsToReportURL(t *testing.T) {
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		assert.Equal(t, "token", r.Header.Get("X-Token"))
		received <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "report.json")
	cmd := newReportCmd(t, "--format", "json", "--output", output, "--report-url", server.URL, "--report-header", "X-Token=token")

	err := WriteReport(t.Context(), cmd, newReport(t, 5.1))

	require.NoError(t, err)
	var r jsonReport
	require.NoError(t, json.Unmarshal(<-received, &r))
	assert.Len(t, r.Findings, 1)
}

func TestWriteReportWithInvalidFormat(t *testing.T) {
	cmd := newReportCmd(t, "--format", "unknown")

	err := WriteReport(t.Context(), cmd, newReport(t))

	assert.Error(t, err)
}
