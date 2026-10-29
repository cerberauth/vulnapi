package discover

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/harnessx"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func NewAPICmd() (apiCmd *cobra.Command) {
	apiCmd = &cobra.Command{
		Use:   "api [url]",
		Short: "Discover api endpoints and server information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			if args[0] == "" {
				telemetryx.Fatal(cmd, telemetryx.Reason(errors.New("url is required"), "url-is-required"))
			}

			parsedUrl, err := url.Parse(args[0])
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-url"))
			}

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-client"))
			}
			headers, cookies, err := cobracurl.BuildRequestHeaders(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-building-request-headers"))
			}
			client = client.WithHeader(headers).WithCookies(cookies)

			engine := harnessx.New()
			s, err := scenario.NewDiscoverAPIScan(engine, http.MethodGet, parsedUrl, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-scan"))
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

			if err := internalCmd.WriteReport(ctx, cmd, reporter); err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-printing-report"))
			}

		},
	}

	internalCmd.AddCommonArgs(apiCmd)

	return apiCmd
}
