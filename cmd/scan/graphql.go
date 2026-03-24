package scan

import (
	"log"

	"github.com/cerberauth/cobracurl"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func NewGraphQLScanCmd() (scanCmd *cobra.Command) {
	var (
		includeScans      []string
		excludeScans      []string
		reportFormat      string
		reportTransport   string
		reportFile        string
		reportURL         string
		noProgress        bool
		severityThreshold float64
	)

	scanCmd = &cobra.Command{
		Use:   "graphql [endpoint]",
		Short: "GraphQL scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			req, err := cobracurl.BuildRequest(cmd, args)
			if err != nil {
				log.Fatal(err)
			}

			otelIncludeScansAttribute := includeScansAttributeKey.StringSlice(internalCmd.FilterScans(includeScans))
			otelExcludeScansAttribute := excludeScansAttributeKey.StringSlice(internalCmd.FilterScans(excludeScans))
			otelAttributes := []attribute.KeyValue{
				otelIncludeScansAttribute,
				otelExcludeScansAttribute,
			}

			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryScanGraphQLSuccessCounter, _ := telemetryMeter.Int64Counter("scan.graphql.success.counter")
			telemetryScanGraphQLErrorCounter, _ := telemetryMeter.Int64Counter("scan.graphql.error.counter")
			ctx := cmd.Context()

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid client"))...))
				log.Fatal(err)
			}
			// Transfer headers and cookies from the built request onto the vulnapi client
			client = client.WithHeader(req.Header).WithCookies(req.Cookies())
			request.SetDefaultClient(client)

			// Set package-level report vars used by PrintOrExportReport
			internalCmd.SetReportFile(reportFile)
			internalCmd.SetReportURL(reportURL)
			internalCmd.SetSeverityThreshold(severityThreshold)

			s, err := scenario.NewGraphQLScan(req.URL, client, &scan.ScanOptions{
				IncludeScans: internalCmd.FilterScans(includeScans),
				ExcludeScans: internalCmd.FilterScans(excludeScans),
			})
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid scenario"))...))
				log.Fatal(err)
			}

			var bar *progressbar.ProgressBar
			if !noProgress {
				bar = internalCmd.NewProgressBar(len(s.GetOperationsScans()))
				// nolint:errcheck
				defer bar.Finish()
			}
			reporter, _, err := s.Execute(ctx, func(operationScan *scan.OperationScan) {
				if bar != nil {
					// nolint:errcheck
					bar.Add(1)
				}
			})
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error executing scenario"))...))
				log.Fatal(err)
			}

			err = internalCmd.PrintOrExportReport(reportFormat, reportTransport, reporter)
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error printing report"))...))
				log.Fatal(err)
			}

			telemetryScanGraphQLSuccessCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))
		},
	}

	cobracurl.RegisterFlags(scanCmd.Flags())

	// vulnapi-specific flags (no conflicting shorthands with cobracurl)
	scanCmd.Flags().StringArrayVar(&includeScans, "scans", nil, "Include specific scans")
	scanCmd.Flags().StringArrayVar(&excludeScans, "exclude-scans", nil, "Exclude specific scans")
	scanCmd.Flags().StringVar(&reportFormat, "report-format", "table", "Report format (table, json, yaml)")
	scanCmd.Flags().StringVar(&reportTransport, "report-transport", "file", "The transport to use for report (e.g. file, http)")
	scanCmd.Flags().StringVar(&reportFile, "report-file", "", "The file to write the report to")
	scanCmd.Flags().StringVar(&reportURL, "report-url", "", "The URL to send the report to")
	scanCmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress output")
	scanCmd.Flags().Float64Var(&severityThreshold, "severity-threshold", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")

	return scanCmd
}
