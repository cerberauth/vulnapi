package scan

import (
	"bufio"
	"errors"
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

			ctx := cmd.Context()

			openapiUrlOrPath := args[0]
			if openapiUrlOrPath == "" {
				telemetryx.Fatal(cmd, telemetryx.Reason(errors.New("OpenAPI path is required"), "openapi-path-is-required"))
			}

			doc, err := openapi.LoadOpenAPI(ctx, openapiUrlOrPath)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-loading-openapi"))
			}

			if err := doc.Validate(ctx); err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-openapi"))
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

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-creating-http-client"))
			}
			headers, cookies, err := cobracurl.BuildRequestHeaders(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-building-request-headers"))
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
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-scenario"))
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
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-executing-scan"))
			}

			if err = internalCmd.WriteReport(ctx, cmd, reporter); err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-printing-report"))
			}

			internalCmd.ExitIfFindings(cmd, reporter, len(internalCmd.GetIncludeScans()) > 0 || internalCmd.GetOnlyScansAboveThreshold())
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	scanCmd.Flags().StringToStringVarP(&securitySchemesValueArg, "security-schemes", "", nil, "Example value for each security scheme")
	return scanCmd
}
