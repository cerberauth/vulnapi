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

var (
	methodAttributeKey = attribute.Key("method")
)

func NewCURLScanCmd() (scanCmd *cobra.Command) {
	var (
		curlMethod string
		curlData   string
	)

	scanCmd = &cobra.Command{
		Use:   "curl [URL]",
		Short: "CURL style Scan",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			otelMethodAttribute := methodAttributeKey.String(curlMethod)
			otelIncludeScansAttribute := includeScansAttributeKey.StringSlice(internalCmd.GetIncludeScans())
			otelExcludeScansAttribute := excludeScansAttributeKey.StringSlice(internalCmd.GetExcludeScans())
			otelAttributes := []attribute.KeyValue{
				otelMethodAttribute,
				otelIncludeScansAttribute,
				otelExcludeScansAttribute,
			}

			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryScanCurlSuccessCounter, _ := telemetryMeter.Int64Counter("scan.curl.success.counter")
			telemetryScanCurlErrorCounter, _ := telemetryMeter.Int64Counter("scan.curl.error.counter")
			ctx := cmd.Context()

			if args[0] == "" {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("url is required"))...))
				log.Fatal("URL is required")
			}

			parsedUrl, err := url.Parse(args[0])
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid url"))...))
				log.Fatal(err)
			}

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid client"))...))
				log.Fatal(err)
			}
			request.SetDefaultClient(client)

			s, err := scenario.NewURLScan(curlMethod, parsedUrl, curlData, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid scenario"))...))
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
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error executing scenario"))...))
				log.Fatal(err)
			}

			err = internalCmd.PrintOrExportReport(internalCmd.GetReportFormat(), internalCmd.GetReportTransport(), reporter)
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error printing report"))...))
				log.Fatal(err)
			}

			telemetryScanCurlSuccessCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	internalCmd.AddPlaceholderArgs(scanCmd)
	scanCmd.Flags().StringVarP(&curlMethod, "request", "X", "GET", "Specify request method to use")
	scanCmd.Flags().StringVarP(&curlData, "data", "d", "", "HTTP POST data")

	return scanCmd
}
