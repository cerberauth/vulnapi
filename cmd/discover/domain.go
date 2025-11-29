package discover

import (
	"fmt"
	"log"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/metric"
)

func NewDomainCmd() (domainCmd *cobra.Command) {
	domainCmd = &cobra.Command{
		Use:   "domain [domain]",
		Short: "Discover subdomains with API endpoints",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
			telemetryDiscoverDomainSuccessCounter, _ := telemetryMeter.Int64Counter("discover.domain.success.counter")
			telemetryDiscoverDomainErrorCounter, _ := telemetryMeter.Int64Counter("discover.domain.error.counter")
			ctx := cmd.Context()

			domain := args[0]

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				telemetryDiscoverDomainErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("invalid client")))
				log.Fatal(err)
			}

			fmt.Printf("Discovering APIs for %s\n", domain)
			scans, err := scenario.NewDiscoverDomainsScan(domain, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				telemetryDiscoverDomainErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("invalid scan")))
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
					telemetryDiscoverDomainErrorCounter.Add(ctx, 1, metric.WithAttributes(otelErrorReasonAttributeKey.String("error executing scan")))
					log.Fatal(err)
				}

				printtable.WellKnownPathsScanReport(reporter)
				printtable.FingerprintScanReport(reporter)

				telemetryDiscoverDomainSuccessCounter.Add(ctx, 1)
			}
		},
	}

	internalCmd.AddCommonArgs(domainCmd)

	return domainCmd
}
