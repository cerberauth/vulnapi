package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var reporter *report.Reporter

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan [type]",
		Short: "API Scan",
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan")

			if reporter == nil {
				return
			}

			fmt.Println()
			fmt.Println()
			ContextualScanReport(reporter)
			DisplayReportTable(reporter)

			analyticsx.TrackEvent(ctx, tracer, "Scan Report", []attribute.KeyValue{
				attribute.Int("vulnerabilityCount", len(reporter.GetVulnerabilityReports())),
				attribute.Bool("hasVulnerability", reporter.HasVulnerability()),
				attribute.Bool("hasHighRiskSeverityVulnerability", reporter.HasHighRiskOrHigherSeverityVulnerability()),
			})
		},
	}

	scanCmd.AddCommand(NewCURLScanCmd())
	scanCmd.AddCommand(NewOpenAPIScanCmd())
	scanCmd.AddCommand(NewGraphQLScanCmd())
	scanCmd.AddCommand(NewDiscoverCmd())

	return scanCmd
}
