package cmd_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteReport_ConfigOutputsSuppressionsAndURL(t *testing.T) {
	t.Setenv("VULNAPI_TEST_REPORT_TOKEN", "s3cr3t")
	var received struct {
		authorization string
		body          []byte
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.authorization = r.Header.Get("Authorization")
		received.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	dir := t.TempDir()
	path := writeConfig(t, dir, "vulnapi.yaml", `version: 1
report:
  outputs:
    - { format: json, path: reports/report.json }
    - { format: sarif, path: reports/report.sarif }
  url: `+server.URL+`
  headers:
    Authorization: { env: VULNAPI_TEST_REPORT_TOKEN }
suppressions:
  - check: jwt.alg_none
    reason: accepted for the test
    expires: 2999-01-01
`)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "reports"), 0o700))
	c := newReportCmd(t, "--quiet")
	cmd.AddConfigFlags(c.Flags())
	require.NoError(t, c.ParseFlags([]string{"--config", path}))
	settings, err := cmd.ResolveScanSettings(c)
	require.NoError(t, err)

	r := newReport(t)
	require.NoError(t, cmd.WriteReport(context.Background(), c, r, settings))

	assert.Equal(t, reportx.StatusAcceptedRisk, r.Findings[0].Status)
	content, err := os.ReadFile(filepath.Join(dir, "reports", "report.json"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "accepted for the test")
	sarif, err := os.ReadFile(filepath.Join(dir, "reports", "report.sarif"))
	require.NoError(t, err)
	assert.True(t, json.Valid(sarif))
	assert.Equal(t, "s3cr3t", received.authorization)
	assert.True(t, json.Valid(received.body))
}
