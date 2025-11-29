package scan

import (
	"log"
	"net/url"

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
	scanCmd = &cobra.Command{
		Use:   "graphql [endpoint]",
		Short: "GraphQL scan",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			otelIncludeScansAttribute := includeScansAttributeKey.StringSlice(internalCmd.GetIncludeScans())
			otelExcludeScansAttribute := excludeScansAttributeKey.StringSlice(internalCmd.GetExcludeScans())
			otelAttributes := []attribute.KeyValue{
				otelIncludeScansAttribute,
				otelExcludeScansAttribute,
			}

			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryScanGraphQLSuccessCounter, _ := telemetryMeter.Int64Counter("scan.graphql.success.counter")
			telemetryScanGraphQLErrorCounter, _ := telemetryMeter.Int64Counter("scan.graphql.error.counter")
			ctx := cmd.Context()

			if args[0] == "" {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("endpoint url is required"))...))
				log.Fatal("Endpoint url is required")
			}

			parsedUrl, err := url.Parse(args[0])
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid url"))...))
				log.Fatal(err)
			}

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid client"))...))
				log.Fatal(err)
			}
			request.SetDefaultClient(client)

			s, err := scenario.NewGraphQLScan(parsedUrl, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid scenario"))...))
				log.Fatal(err)
			}

			var bar *progressbar.ProgressBar
			if !internalCmd.GetNoProgress() {
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

			err = internalCmd.PrintOrExportReport(internalCmd.GetReportFormat(), internalCmd.GetReportTransport(), reporter)
			if err != nil {
				telemetryScanGraphQLErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error printing report"))...))
				log.Fatal(err)
			}

			telemetryScanGraphQLSuccessCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	internalCmd.AddPlaceholderArgs(scanCmd)

	return scanCmd
}
