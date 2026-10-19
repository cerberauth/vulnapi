package discover

import (
	"fmt"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/harnessx"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func NewDomainCmd() (domainCmd *cobra.Command) {
	domainCmd = &cobra.Command{
		Use:   "domain [domain]",
		Short: "Discover subdomains with API endpoints",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()

			domain := args[0]

			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-client"))
			}
			headers, cookies, err := cobracurl.BuildRequestHeaders(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-building-request-headers"))
			}
			client = client.WithHeader(headers).WithCookies(cookies)

			fmt.Printf("Discovering APIs for %s\n", domain)
			engine := harnessx.New()
			scans, err := scenario.NewDiscoverDomainsScan(engine, domain, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-scan"))
			}
			fmt.Printf("Found %d Domains\n", len(scans))

			for _, s := range scans {
				fmt.Println()
				fmt.Printf("Scanning %s\n", s.Operations[0].URL.String())

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

			}
		},
	}

	internalCmd.AddCommonArgs(domainCmd)

	return domainCmd
}
