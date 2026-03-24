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
			includeScans      []string
			excludeScans      []string
			outputFormat      string
			outputTransport   string
			noProgress        bool
			severityThreshold float64
		}
	}{
		{
			name: "default values",
			args: []string{},
			expected: struct {
				includeScans      []string
				excludeScans      []string
				outputFormat      string
				outputTransport   string
				noProgress        bool
				severityThreshold float64
			}{
				includeScans:      nil,
				excludeScans:      nil,
				outputFormat:      "table",
				outputTransport:   "file",
				noProgress:        false,
				severityThreshold: 1,
			},
		},
		{
			name: "custom values",
			args: []string{
				"--proxy=http://proxy.example.com",
				"--header=Authorization: Bearer token",
				"--cookie=sessionid=12345",
				"--scans=scan1",
				"--scans=scan2",
				"--report-format=json",
				"--report-transport=http",
				"--report-file=/tmp/output",
				"--report-url=http://example.com/output",
				"--no-progress",
				"--severity-threshold=5",
			},
			expected: struct {
				includeScans      []string
				excludeScans      []string
				outputFormat      string
				outputTransport   string
				noProgress        bool
				severityThreshold float64
			}{
				includeScans:      []string{"scan1", "scan2"},
				excludeScans:      nil,
				outputFormat:      "json",
				outputTransport:   "http",
				noProgress:        true,
				severityThreshold: 5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd.ClearValues()
			testCmd := &cobra.Command{}
			cmd.AddCommonArgs(testCmd)
			testCmd.SetArgs(tt.args)
			testCmd.Execute()

			assert.Equal(t, tt.expected.includeScans, cmd.GetIncludeScans())
			assert.Equal(t, tt.expected.excludeScans, cmd.GetExcludeScans())
			assert.Equal(t, tt.expected.outputFormat, cmd.GetReportFormat())
			assert.Equal(t, tt.expected.outputTransport, cmd.GetReportTransport())
			assert.Equal(t, tt.expected.noProgress, cmd.GetNoProgress())
			assert.Equal(t, tt.expected.severityThreshold, cmd.GetSeverityThreshold())
		})
	}
}
