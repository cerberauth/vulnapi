package scan

import (
	"bufio"
	"log"
	"os"

	"github.com/cerberauth/vulnapi/internal/analytics"
	"github.com/cerberauth/vulnapi/internal/auth"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"
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
			openapiUrlOrPath := args[0]

			ctx, span := tracer.Start(cmd.Context(), "Scan OpenAPI")
			defer span.End()

			openapi, err := openapi.LoadOpenAPI(ctx, openapiUrlOrPath)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}

			if err := openapi.Validate(ctx); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
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
			securitySchemesValues := auth.NewSecuritySchemeValues(values).WithDefault(validToken)

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}
			request.SetDefaultClient(client)

			s, err := scenario.NewOpenAPIScan(openapi, securitySchemesValues, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
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
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}

			analytics.TrackScanReport(ctx, reporter)
			if err = internalCmd.PrintOrExportReport(internalCmd.GetReportFormat(), internalCmd.GetReportTransport(), reporter); err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	scanCmd.Flags().StringToStringVarP(&securitySchemesValueArg, "security-schemes", "", nil, "Example value for each security scheme")
	return scanCmd
}
