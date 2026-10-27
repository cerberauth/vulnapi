package scan

import (
	"log"
	"os"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/harnessx"
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

func NewOpenAPIScanCmd() (scanCmd *cobra.Command) {
	var (
		securitySchemesValueArg map[string]string
		tokenStdin              bool
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
			switch {
			case tokenStdin:
				validToken, err = readToken(os.Stdin)
				if err != nil {
					telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error reading token from stdin"))...))
					log.Fatal(err)
				}
			case !cmd.Flags().Changed("token-stdin") && isStdinOpen():
				// Deprecated: reading a piped token without --token-stdin.
				// Pass --token-stdin=false to skip it, e.g. in CI where
				// stdin can be an open pipe that never closes.
				if validToken, err = readToken(os.Stdin); err == nil {
					cmd.PrintErrln("Warning: reading the token from stdin without --token-stdin is deprecated; pass --token-stdin")
				}
			}

			values := make(map[string]interface{}, len(securitySchemesValueArg))
			for key, value := range securitySchemesValueArg {
				values[key] = &value
			}
			securitySchemesValues := openapi.NewSecuritySchemeValues(values).WithDefault(validToken)

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error creating http client"))...))
				log.Fatal(err)
			}
			headers, cookies, err := cobracurl.BuildRequestHeaders(cmd)
			if err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error building request headers"))...))
				log.Fatal(err)
			}
			client = client.WithHeader(headers).WithCookies(cookies)
			request.SetDefaultClient(client)

			engine := harnessx.New()
			s, err := scenario.NewOpenAPIScan(ctx, engine, doc, securitySchemesValues, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
				MinSeverity:  internalCmd.GetMinSeverity(),
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

			if err = internalCmd.WriteReport(ctx, cmd, reporter); err != nil {
				telemetryScanOpenAPIErrorCounter.Add(ctx, 1, metric.WithAttributes(append(otelAttributes, otelErrorReasonAttributeKey.String("error printing report"))...))
				log.Fatal(err)
			}

			telemetryScanOpenAPISuccessCounter.Add(ctx, 1, metric.WithAttributes(otelAttributes...))

			internalCmd.ExitIfFindings(reporter, len(internalCmd.GetIncludeScans()) > 0 || internalCmd.GetOnlyScansAboveThreshold())
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	scanCmd.Flags().StringToStringVarP(&securitySchemesValueArg, "security-schemes", "", nil, "Example value for each security scheme")
	scanCmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "Read the default security scheme token from stdin")
	return scanCmd
}
