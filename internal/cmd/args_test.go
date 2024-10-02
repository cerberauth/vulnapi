package cmd_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestAddCommonArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected struct {
			rateLimit         string
			proxy             string
			headers           []string
			cookies           []string
			includeScans      []string
			excludeScans      []string
			outputFormat      string
			outputTransport   string
			outputPath        string
			outputURL         string
			noProgress        bool
			severityThreshold float64
		}
	}{
		{
			name: "default values",
			args: []string{},
			expected: struct {
				rateLimit         string
				proxy             string
				headers           []string
				cookies           []string
				includeScans      []string
				excludeScans      []string
				outputFormat      string
				outputTransport   string
				outputPath        string
				outputURL         string
				noProgress        bool
				severityThreshold float64
			}{
				rateLimit:         "10/s",
				proxy:             "",
				headers:           nil,
				cookies:           nil,
				includeScans:      nil,
				excludeScans:      nil,
				outputFormat:      "table",
				outputTransport:   "file",
				outputPath:        "",
				outputURL:         "",
				noProgress:        false,
				severityThreshold: 1,
			},
		},
		{
			name: "custom values",
			args: []string{
				"--rate-limit=5/m",
				"--proxy=http://proxy.example.com",
				"--header=Authorization: Bearer token",
				"--cookie=sessionid=12345",
				"--scans=scan1",
				"--scans=scan2",
				"--format=json",
				"--output-transport=http",
				"--output-path=/tmp/output",
				"--output-url=http://example.com/output",
				"--no-progress",
				"--severity-threshold=5",
			},
			expected: struct {
				rateLimit         string
				proxy             string
				headers           []string
				cookies           []string
				includeScans      []string
				excludeScans      []string
				outputFormat      string
				outputTransport   string
				outputPath        string
				outputURL         string
				noProgress        bool
				severityThreshold float64
			}{
				rateLimit:         "5/m",
				proxy:             "http://proxy.example.com",
				headers:           []string{"Authorization: Bearer token"},
				cookies:           []string{"sessionid=12345"},
				includeScans:      []string{"scan1", "scan2"},
				excludeScans:      nil,
				outputFormat:      "json",
				outputTransport:   "http",
				outputPath:        "/tmp/output",
				outputURL:         "http://example.com/output",
				noProgress:        true,
				severityThreshold: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testCmd := &cobra.Command{}
			cmd.AddCommonArgs(testCmd)
			testCmd.SetArgs(tt.args)
			testCmd.Execute()

			assert.Equal(t, tt.expected.rateLimit, cmd.GetRateLimit())
			assert.Equal(t, tt.expected.proxy, cmd.GetProxy())
			assert.Equal(t, tt.expected.headers, cmd.GetHeaders())
			assert.Equal(t, tt.expected.cookies, cmd.GetCookies())
			assert.Equal(t, tt.expected.includeScans, cmd.GetIncludeScans())
			assert.Equal(t, tt.expected.excludeScans, cmd.GetExcludeScans())
			assert.Equal(t, tt.expected.outputFormat, cmd.GetOutputFormat())
			assert.Equal(t, tt.expected.outputTransport, cmd.GetOutputTransport())
			assert.Equal(t, tt.expected.noProgress, cmd.GetNoProgress())
			assert.Equal(t, tt.expected.severityThreshold, cmd.GetSeverityThreshold())
		})
	}
}
