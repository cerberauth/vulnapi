package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	vulnapimcp "github.com/cerberauth/vulnapi/cmd/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const helperEnv = "VULNAPI_MCP_TEST_HELPER"

// TestMain lets the test binary act as the "mcp" command when started by
// TestServeOverStdio, so the stdio transport is exercised for real.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		root := &cobra.Command{Use: "vulnapi", SilenceUsage: true}
		root.AddCommand(vulnapimcp.NewMCPCmd())
		root.SetArgs(os.Args[1:])
		if err := root.Execute(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestMCPCmdRequiresAnAllowedHost(t *testing.T) {
	cmd := vulnapimcp.NewMCPCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--allow-host")
}

func TestMCPCmdRejectsAURLAsAllowedHost(t *testing.T) {
	cmd := vulnapimcp.NewMCPCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs([]string{"--allow-host", "http://localhost:8080"})
	assert.Error(t, cmd.Execute())
}

func TestServeOverStdio(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer api.Close()
	host := strings.TrimPrefix(api.URL, "http://")

	command := exec.Command(os.Args[0], "mcp", "--allow-host", host, "--rate", "1000")
	command.Env = append(os.Environ(), helperEnv+"=1")
	command.Stderr = os.Stderr

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &sdk.CommandTransport{Command: command}, nil)
	require.NoError(t, err)
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	assert.Contains(t, names, "scan_curl")
	assert.Contains(t, names, "scan_openapi")

	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "scan_curl", Arguments: map[string]any{"url": api.URL + "/"}})
	require.NoError(t, err)
	require.False(t, result.IsError)
	raw, err := json.Marshal(result.StructuredContent)
	require.NoError(t, err)
	var report struct {
		Findings []map[string]any `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(raw, &report))
	assert.NotEmpty(t, report.Findings)

	refused, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "scan_curl", Arguments: map[string]any{"url": "http://example.com/"}})
	require.NoError(t, err)
	assert.True(t, refused.IsError)
}
