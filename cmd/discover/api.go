package discover

import (
	"log"
	"net/http"
	"net/url"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/metric"
)

func NewAPICmd() (apiCmd *cobra.Command) {
	apiCmd = &cobra.Command{
		Use:   "api [url]",
		Short: "Discover api endpoints and server information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryDiscoverApiSuccessCounter, _ := telemetryMeter.Int64Counter("discover.api.success.counter")
			telemetryDiscoverApiErrorCounter, _ := telemetryMeter.Int64Counter("discover.api.error.counter")
			ctx := cmd.Context()

			if args[0] == "" {
				telemetryDiscoverApiErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("url is required")))
				log.Fatal("url is required")
			}

			parsedUrl, err := url.Parse(args[0])
			if err != nil {
				telemetryDiscoverApiErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("invalid url")))
				log.Fatal(err)
			}

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				telemetryDiscoverApiErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("invalid client")))
				log.Fatal(err)
			}

			s, err := scenario.NewDiscoverAPIScan(http.MethodGet, parsedUrl, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryDiscoverApiErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("invalid scan")))
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
				telemetryDiscoverApiErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("error executing scan")))
				log.Fatal(err)
			}

			printtable.WellKnownPathsScanReport(reporter)
			printtable.FingerprintScanReport(reporter)

			telemetryDiscoverApiSuccessCounter.Add(ctx, 1)
		},
	}

	internalCmd.AddCommonArgs(apiCmd)

	return apiCmd
}
