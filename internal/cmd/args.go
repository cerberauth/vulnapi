package cmd

import (
	"github.com/cerberauth/cobracurl"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/spf13/cobra"
)

var (
	includeScans []string
	excludeScans []string

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

	cobrareportx.RegisterFormatFlags(cmd)
	cobrareportx.RegisterTransportFlags(cmd)

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

func GetNoProgress() bool {
	return noProgress
}

func GetSeverityThreshold() float64 {
	return severityThreshold
}

func SetSeverityThreshold(t float64) {
	severityThreshold = t
}

func ClearValues() {
	includeScans = []string{}
	excludeScans = []string{}
	noProgress = false
	severityThreshold = 1
}
