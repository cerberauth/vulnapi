package discover

import (
	"fmt"
	"log"

	"github.com/cerberauth/vulnapi/internal/analytics"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"
)

func NewDomainCmd() (domainCmd *cobra.Command) {
	domainCmd = &cobra.Command{
		Use:   "domain [domain]",
		Short: "Discover subdomains with API endpoints",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			domain := args[0]

			ctx, span := tracer.Start(cmd.Context(), "Discover Domain")
			defer span.End()

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies(), internalCmd.GetInsecure())
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}

			fmt.Printf("Discovering APIs for %s\n", domain)
			scans, err := scenario.NewDiscoverDomainsScan(domain, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
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
					span.RecordError(err)
					span.SetStatus(codes.Error, err.Error())
					log.Fatal(err)
				}

				analytics.TrackScanReport(ctx, reporter)
				printtable.WellKnownPathsScanReport(reporter)
				printtable.FingerprintScanReport(reporter)
			}
		},
	}

	internalCmd.AddCommonArgs(domainCmd)

	return domainCmd
}
