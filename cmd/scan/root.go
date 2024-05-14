package scan

import (
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

			DisplayReportTable(reporter)

			analyticsx.TrackEvent(ctx, tracer, "Scan Report", []attribute.KeyValue{
				attribute.Int("vulnerabilityCount", len(reporter.GetVulnerabilityReports())),
				attribute.Bool("hasVulnerability", reporter.HasVulnerability()),
				attribute.Bool("hasHighRiskSeverityVulnerability", reporter.HasHighRiskSeverityVulnerability()),
			})
		},
	}

	scanCmd.AddCommand(NewCURLScanCmd())
	scanCmd.AddCommand(NewOpenAPIScanCmd())
	scanCmd.AddCommand(NewGraphQLScanCmd())

	return scanCmd
}
