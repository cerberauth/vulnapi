package scan

import (
	"io"
	"log"

	"github.com/cerberauth/cobracurl"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
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
		includeScans      []string
		excludeScans      []string
		noProgress        bool
		severityThreshold float64
	)

	scanCmd = &cobra.Command{
		Use:   "curl [URL]",
		Short: "CURL style Scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			req, err := cobracurl.BuildRequest(cmd, args)
			if err != nil {
				log.Fatal(err)
			}

			otelMethodAttribute := methodAttributeKey.String(req.Method)
			otelIncludeScansAttribute := includeScansAttributeKey.StringSlice(internalCmd.FilterScans(includeScans))
			otelExcludeScansAttribute := excludeScansAttributeKey.StringSlice(internalCmd.FilterScans(excludeScans))
			otelAttributes := []attribute.KeyValue{
				otelMethodAttribute,
				otelIncludeScansAttribute,
				otelExcludeScansAttribute,
			}

			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryScanCurlSuccessCounter, _ := telemetryMeter.Int64Counter("scan.curl.success.counter")
			telemetryScanCurlErrorCounter, _ := telemetryMeter.Int64Counter("scan.curl.error.counter")
			ctx := cmd.Context()

			var curlData string
			if req.Body != nil {
				bodyBytes, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error reading body"))...))
					log.Fatal(readErr)
				}
				curlData = string(bodyBytes)
			}

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid client"))...))
				log.Fatal(err)
			}
			client = client.WithHeader(req.Header).WithCookies(req.Cookies())
			request.SetDefaultClient(client)

			internalCmd.SetSeverityThreshold(severityThreshold)

			s, err := scenario.NewURLScan(req.Method, req.URL, curlData, client, &scan.ScanOptions{
				IncludeScans: internalCmd.FilterScans(includeScans),
				ExcludeScans: internalCmd.FilterScans(excludeScans),
			})
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid scenario"))...))
				log.Fatal(err)
			}

			var bar *progressbar.ProgressBar
			if !noProgress {
				bar = internalCmd.NewProgressBar(len(s.GetOperationsScans()))
				defer func() { _ = bar.Finish() }()
			}
			reporter, _, err := s.Execute(ctx, func(operationScan *scan.OperationScan) {
				if bar != nil {
					_ = bar.Add(1)
				}
			})
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error executing scenario"))...))
				log.Fatal(err)
			}

			err = internalCmd.WriteReport(ctx, cmd, reporter)
			if err != nil {
				telemetryScanCurlErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error printing report"))...))
				log.Fatal(err)
			}

			telemetryScanCurlSuccessCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))

			internalCmd.ExitIfFindings(reporter, len(internalCmd.FilterScans(includeScans)) > 0)
		},
	}

	cobracurl.RegisterFlags(scanCmd.Flags())

	scanCmd.Flags().StringArrayVar(&includeScans, "scans", nil, "Include specific scans")
	scanCmd.Flags().StringArrayVar(&excludeScans, "exclude-scans", nil, "Exclude specific scans")
	cobrareportx.RegisterFormatFlags(scanCmd)
	cobrareportx.RegisterTransportFlags(scanCmd)
	scanCmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress output")
	scanCmd.Flags().Float64Var(&severityThreshold, "severity-threshold", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")

	return scanCmd
}
