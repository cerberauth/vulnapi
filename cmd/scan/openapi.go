package scan

import (
	"errors"
	"fmt"
	"net/url"
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

func NewOpenAPIScanCmd() (scanCmd *cobra.Command) {
	var (
		securitySchemesValueArg map[string]string
		tokenStdin              bool
		serverUrl               string
	)

	scanCmd = &cobra.Command{
		Use:   "openapi [OpenAPIPath]",
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

			if serverUrl != "" {
				baseUrl, err := url.Parse(serverUrl)
				if err != nil || baseUrl.Scheme == "" || baseUrl.Host == "" {
					telemetryx.Fatal(cmd, telemetryx.Reason(fmt.Errorf("invalid --server-url %q: an absolute URL is required", serverUrl), "invalid-server-url"))
				}
				if baseUrl.Path == "" {
					baseUrl.Path = "/"
				}
				doc.SetBaseUrl(baseUrl)
			}

			if err := doc.Validate(ctx); err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-openapi"))
			}

			var validToken *string
			switch {
			case tokenStdin:
				validToken, err = readToken(os.Stdin)
				if err != nil {
					telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-reading-token-from-stdin"))
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
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-creating-http-client"))
			}
			headers, cookies, err := cobracurl.BuildRequestHeaders(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-building-request-headers"))
			}
			client = client.WithHeader(headers).WithCookies(cookies)
			request.SetDefaultClient(client)

			internalCmd.ApplyJWTSecretFlag(cmd)

			engine := harnessx.New()
			s, err := scenario.NewOpenAPIScan(ctx, engine, doc, securitySchemesValues, client, &scan.ScanOptions{
				ToolVersion:        internalCmd.Version(cmd),
				AllowUnsafeMethods: internalCmd.GetAllowUnsafeMethods(),
				IncludeScans:       internalCmd.GetIncludeScans(),
				ExcludeScans:       internalCmd.GetExcludeScans(),
				MinSeverity:        internalCmd.GetMinSeverity(),
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
	scanCmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "Read the default security scheme token from stdin")
	scanCmd.Flags().StringVar(&serverUrl, "server-url", "", "Base URL of the API, overriding the servers of the OpenAPI document")
	return scanCmd
}
