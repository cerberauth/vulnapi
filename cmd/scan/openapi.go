package scan

import (
	"bufio"
	"log"
	"os"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func isStdinOpen() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func readStdin() *string {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		t := scanner.Text()
		return &t
	}

	return nil
}

func NewOpenAPIScanCmd() (scanCmd *cobra.Command) {
	var (
		securitySchemesValueArg map[string]string
	)

	scanCmd = &cobra.Command{
		Use:   "openapi [OpenAPIPAth]",
		Short: "OpenAPI Operations Scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			otelIncludeScansAttribute := includeScansAttributeKey.StringSlice(internalCmd.GetIncludeScans())
			otelExcludeScansAttribute := excludeScansAttributeKey.StringSlice(internalCmd.GetExcludeScans())
			otelAttributes := []attribute.KeyValue{
				otelIncludeScansAttribute,
				otelExcludeScansAttribute,
			}

			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryScanOpenAPISuccessCounter, _ := telemetryMeter.Int64Counter("scan.openapi.success.counter")
			telemetryScanOpenAPIErrorCounter, _ := telemetryMeter.Int64Counter("scan.openapi.error.counter")
			ctx := cmd.Context()

			openapiUrlOrPath := args[0]
			if openapiUrlOrPath == "" {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("openapi path is required"))...))
				log.Fatal("OpenAPI path is required")
			}

			doc, err := openapi.LoadOpenAPI(ctx, openapiUrlOrPath)
			if err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error loading openapi"))...))
				log.Fatal(err)
			}

			if err := doc.Validate(ctx); err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid openapi"))...))
				log.Fatal(err)
			}

			var validToken *string
			if isStdinOpen() {
				validToken = readStdin()
			}

			values := make(map[string]interface{}, len(securitySchemesValueArg))
			for key, value := range securitySchemesValueArg {
				values[key] = &value
			}
			securitySchemesValues := openapi.NewSecuritySchemeValues(values).WithDefault(validToken)

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error creating http client"))...))
				log.Fatal(err)
			}
			request.SetDefaultClient(client)

			s, err := scenario.NewOpenAPIScan(ctx, doc, securitySchemesValues, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("invalid scenario"))...))
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
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error executing scan"))...))
				log.Fatal(err)
			}

			if err = internalCmd.PrintOrExportReport(internalCmd.GetReportFormat(), internalCmd.GetReportTransport(), reporter); err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error printing report"))...))
				log.Fatal(err)
			}

			telemetryScanOpenAPISuccessCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	scanCmd.Flags().StringToStringVarP(&securitySchemesValueArg, "security-schemes", "", nil, "Example value for each security scheme")
	return scanCmd
}
