package discover

import (
	"fmt"
	"log"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func NewDomainCmd() (domainCmd *cobra.Command) {
	domainCmd = &cobra.Command{
		Use:   "domain [domain]",
		Short: "Discover subdomains with API endpoints",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("discover")
			domain := args[0]

			analyticsx.TrackEvent(ctx, tracer, "Discover Domain", []attribute.KeyValue{})
			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			fmt.Printf("Discovering APIs for %s\n", domain)
			scans, err := scenario.NewDiscoverDomainsScan(domain, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}
			fmt.Printf("Found %d Domains\n", len(scans))

			for _, s := range scans {
				fmt.Println()
				fmt.Printf("Scanning %s\n", s.Operations[0].URL.String())

				bar := internalCmd.NewProgressBar(len(s.GetOperationsScans()))
				reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {
					bar.Add(1)
				}, internalCmd.GetIncludeScans(), internalCmd.GetExcludeScans())
				if err != nil {
					analyticsx.TrackError(ctx, tracer, err)
					log.Fatal(err)
				}

				internalCmd.TrackScanReport(ctx, tracer, reporter)
				printtable.WellKnownPathsScanReport(reporter)
				printtable.ContextualScanReport(reporter)
			}
		},
	}

	internalCmd.AddCommonArgs(domainCmd)

	return domainCmd
}
