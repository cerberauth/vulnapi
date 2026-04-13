package cmd

import (
	"github.com/cerberauth/cobracurl"
	"github.com/spf13/cobra"
)

var (
	includeScans []string
	excludeScans []string

	reportFormat    string
	reportTransport string
	reportFile      string
	reportURL       string

	noProgress        bool
	severityThreshold float64
)

func AddCommonArgs(cmd *cobra.Command) {
	cobracurl.RegisterClientFlags(cmd.Flags())
	cobracurl.RegisterHeaderFlags(cmd.Flags())
	cobracurl.RegisterAuthFlags(cmd.Flags())
	cobracurl.RegisterRateFlag(cmd.Flags())

	cmd.Flags().StringP("rate-limit", "r", "", "Rate limit for requests (e.g. 10/s, 1/m)")
	if err := cmd.Flags().MarkDeprecated("rate-limit", "use --rate instead"); err != nil {
		panic(err)
	}

	cmd.Flags().StringArrayVarP(&includeScans, "scans", "", includeScans, "Include specific scans")
	cmd.Flags().StringArrayVar(&excludeScans, "exclude-scans", excludeScans, "Exclude specific scans")

	cmd.Flags().StringVarP(&reportFormat, "report-format", "", "table", "Report format (table, json, yaml)")
	cmd.Flags().StringVarP(&reportTransport, "report-transport", "", "file", "The transport to use for report (e.g. file, http)")
	cmd.Flags().StringVarP(&reportFile, "report-file", "", "", "The file to write the report to")
	cmd.Flags().StringVarP(&reportURL, "report-url", "", "", "The URL to send the report to")

	cmd.Flags().BoolVarP(&noProgress, "no-progress", "", false, "Disable progress output")
	cmd.Flags().Float64VarP(&severityThreshold, "severity-threshold", "", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")
}

func FilterScans(scans []string) []string {
	var filtered []string
	for _, s := range scans {
		if s != "" {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func GetIncludeScans() []string {
	return FilterScans(includeScans)
}

func GetExcludeScans() []string {
	return FilterScans(excludeScans)
}

func GetReportFormat() string {
	return reportFormat
}

func GetReportTransport() string {
	return reportTransport
}

func GetNoProgress() bool {
	return noProgress
}

func GetSeverityThreshold() float64 {
	return severityThreshold
}

func SetReportFile(f string) {
	reportFile = f
}

func SetReportURL(u string) {
	reportURL = u
}

func SetSeverityThreshold(t float64) {
	severityThreshold = t
}

func ClearValues() {
	includeScans = []string{}
	excludeScans = []string{}
	reportFormat = "table"
	reportTransport = "file"
	reportFile = ""
	reportURL = ""
	noProgress = false
	severityThreshold = 1
}
