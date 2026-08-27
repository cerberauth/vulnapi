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
			reportURL         string
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
				reportURL         string
				noProgress        bool
				severityThreshold float64
			}{
				includeScans:      nil,
				excludeScans:      nil,
				outputFormat:      "terminal",
				reportURL:         "",
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
				"--format=json",
				"--report-url=http://example.com/output",
				"--no-progress",
				"--severity-threshold=5",
			},
			expected: struct {
				includeScans      []string
				excludeScans      []string
				outputFormat      string
				reportURL         string
				noProgress        bool
				severityThreshold float64
			}{
				includeScans:      []string{"scan1", "scan2"},
				excludeScans:      nil,
				outputFormat:      "json",
				reportURL:         "http://example.com/output",
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

			format, _ := testCmd.Flags().GetString("format")
			reportURL, _ := testCmd.Flags().GetString("report-url")

			assert.Equal(t, tt.expected.includeScans, cmd.GetIncludeScans())
			assert.Equal(t, tt.expected.excludeScans, cmd.GetExcludeScans())
			assert.Equal(t, tt.expected.outputFormat, format)
			assert.Equal(t, tt.expected.reportURL, reportURL)
			assert.Equal(t, tt.expected.noProgress, cmd.GetNoProgress())
			assert.Equal(t, tt.expected.severityThreshold, cmd.GetSeverityThreshold())
		})
	}
}
