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
			rateLimit            string
			proxy                string
			headers              []string
			cookies              []string
			authUser             string
			includeScans         []string
			excludeScans         []string
			outputFormat         string
			outputTransport      string
			outputPath           string
			outputURL            string
			noProgress           bool
			severityThreshold    float64
			scanMinIssueSeverity float64
			scanIncludeCWEs      []string
			scanExcludeCWEs      []string
			scanIncludeOWASPs    []string
			scanExcludeOWASPs    []string
		}
	}{
		{
			name: "default values",
			args: []string{},
			expected: struct {
				rateLimit            string
				proxy                string
				headers              []string
				cookies              []string
				authUser             string
				includeScans         []string
				excludeScans         []string
				outputFormat         string
				outputTransport      string
				outputPath           string
				outputURL            string
				noProgress           bool
				severityThreshold    float64
				scanMinIssueSeverity float64
				scanIncludeCWEs      []string
				scanExcludeCWEs      []string
				scanIncludeOWASPs    []string
				scanExcludeOWASPs    []string
			}{
				rateLimit:            "10/s",
				proxy:                "",
				headers:              []string{},
				cookies:              []string{},
				authUser:             "",
				includeScans:         nil,
				excludeScans:         nil,
				outputFormat:         "table",
				outputTransport:      "file",
				outputPath:           "",
				outputURL:            "",
				noProgress:           false,
				severityThreshold:    1,
				scanMinIssueSeverity: 0,
				scanIncludeCWEs:      []string{},
				scanExcludeCWEs:      []string{},
				scanIncludeOWASPs:    []string{},
				scanExcludeOWASPs:    []string{},
			},
		},
		{
			name: "basic auth",
			args: []string{
				"--user=user:password",
				"--scans=scan1",
				"--scans=scan2",
			},
			expected: struct {
				rateLimit            string
				proxy                string
				headers              []string
				cookies              []string
				authUser             string
				includeScans         []string
				excludeScans         []string
				outputFormat         string
				outputTransport      string
				outputPath           string
				outputURL            string
				noProgress           bool
				severityThreshold    float64
				scanMinIssueSeverity float64
				scanIncludeCWEs      []string
				scanExcludeCWEs      []string
				scanIncludeOWASPs    []string
				scanExcludeOWASPs    []string
			}{
				rateLimit:            "10/s",
				proxy:                "",
				headers:              []string{"Authorization: Basic dXNlcjpwYXNzd29yZA=="},
				cookies:              []string{},
				authUser:             "user:password",
				includeScans:         []string{"scan1", "scan2"},
				excludeScans:         nil,
				outputFormat:         "table",
				outputTransport:      "file",
				outputPath:           "",
				outputURL:            "",
				noProgress:           false,
				severityThreshold:    1,
				scanMinIssueSeverity: 0,
				scanIncludeCWEs:      []string{},
				scanExcludeCWEs:      []string{},
				scanIncludeOWASPs:    []string{},
				scanExcludeOWASPs:    []string{},
			},
		},
		{
			name: "basic auth without password",
			args: []string{
				"--user=user",
				"--scans=scan1",
				"--scans=scan2",
			},
			expected: struct {
				rateLimit            string
				proxy                string
				headers              []string
				cookies              []string
				authUser             string
				includeScans         []string
				excludeScans         []string
				outputFormat         string
				outputTransport      string
				outputPath           string
				outputURL            string
				noProgress           bool
				severityThreshold    float64
				scanMinIssueSeverity float64
				scanIncludeCWEs      []string
				scanExcludeCWEs      []string
				scanIncludeOWASPs    []string
				scanExcludeOWASPs    []string
			}{
				rateLimit:            "10/s",
				proxy:                "",
				headers:              []string{},
				cookies:              []string{},
				authUser:             "user",
				includeScans:         []string{"scan1", "scan2"},
				excludeScans:         nil,
				outputFormat:         "table",
				outputTransport:      "file",
				outputPath:           "",
				outputURL:            "",
				noProgress:           false,
				severityThreshold:    1,
				scanMinIssueSeverity: 0,
				scanIncludeCWEs:      []string{},
				scanExcludeCWEs:      []string{},
				scanIncludeOWASPs:    []string{},
				scanExcludeOWASPs:    []string{},
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
				"--report-format=json",
				"--report-transport=http",
				"--report-file=/tmp/output",
				"--report-url=http://example.com/output",
				"--no-progress",
				"--severity-threshold=5",

				"--scan-min-severity=3",
				"--scan-include-cwe=CWE-123",
				"--scan-include-cwe=CWE-456",
				"--scan-exclude-cwe=CWE-789",
				"--scan-include-owasp=OWASP-A1",
				"--scan-include-owasp=OWASP-A2",
				"--scan-exclude-owasp=OWASP-B1",
				"--scan-exclude-owasp=OWASP-B2",
			},
			expected: struct {
				rateLimit            string
				proxy                string
				headers              []string
				cookies              []string
				authUser             string
				includeScans         []string
				excludeScans         []string
				outputFormat         string
				outputTransport      string
				outputPath           string
				outputURL            string
				noProgress           bool
				severityThreshold    float64
				scanMinIssueSeverity float64
				scanIncludeCWEs      []string
				scanExcludeCWEs      []string
				scanIncludeOWASPs    []string
				scanExcludeOWASPs    []string
			}{
				rateLimit:            "5/m",
				proxy:                "http://proxy.example.com",
				headers:              []string{"Authorization: Bearer token"},
				cookies:              []string{"sessionid=12345"},
				authUser:             "",
				includeScans:         []string{"scan1", "scan2"},
				excludeScans:         nil,
				outputFormat:         "json",
				outputTransport:      "http",
				outputPath:           "/tmp/output",
				outputURL:            "http://example.com/output",
				noProgress:           true,
				severityThreshold:    5,
				scanMinIssueSeverity: 3,
				scanIncludeCWEs:      []string{"CWE-123", "CWE-456"},
				scanExcludeCWEs:      []string{"CWE-789"},
				scanIncludeOWASPs:    []string{"OWASP-A1", "OWASP-A2"},
				scanExcludeOWASPs:    []string{"OWASP-B1", "OWASP-B2"},
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

			assert.Equal(t, tt.expected.rateLimit, cmd.GetRateLimit())
			assert.Equal(t, tt.expected.proxy, cmd.GetProxy())
			assert.Equal(t, tt.expected.headers, cmd.GetHeaders())
			assert.Equal(t, tt.expected.cookies, cmd.GetCookies())
			assert.Equal(t, tt.expected.authUser, cmd.GetAuthUser())
			assert.Equal(t, tt.expected.includeScans, cmd.GetIncludeScans())
			assert.Equal(t, tt.expected.excludeScans, cmd.GetExcludeScans())
			assert.Equal(t, tt.expected.outputFormat, cmd.GetReportFormat())
			assert.Equal(t, tt.expected.outputTransport, cmd.GetReportTransport())
			assert.Equal(t, tt.expected.noProgress, cmd.GetNoProgress())
			assert.Equal(t, tt.expected.severityThreshold, cmd.GetSeverityThreshold())
			assert.Equal(t, tt.expected.scanMinIssueSeverity, cmd.GetScanMinIssueSeverity())
			assert.Equal(t, tt.expected.scanIncludeCWEs, cmd.GetScanIncludeCWEs())
			assert.Equal(t, tt.expected.scanExcludeCWEs, cmd.GetScanExcludeCWEs())
			assert.Equal(t, tt.expected.scanIncludeOWASPs, cmd.GetScanIncludeOWASPs())
			assert.Equal(t, tt.expected.scanExcludeOWASPs, cmd.GetScanExcludeOWASPs())
		})
	}
}
