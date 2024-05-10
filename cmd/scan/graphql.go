package scan

import (
	"log"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func NewGraphQLScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "graphql [endpoint]",
		Short: "GraphQL scan",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/graphql")
			graphqlEndpoint := args[0]

			analyticsx.TrackEvent(ctx, tracer, "Scan GraphQL", []attribute.KeyValue{})
			client := NewHTTPClientFromArgs(rateLimit, proxy, headers, cookies)
			s, err := scan.NewGraphQLScan(graphqlEndpoint, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			s.WithAllVulnsScans().WithAllBestPracticesScans().WithAllGraphQLScans()
			bar := newProgressBar(len(s.GetOperationsScans()))

			if reporter, _, err = s.Execute(func(operationScan *scan.OperationScan) {
				bar.Add(1)
			}); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}
		},
	}

	AddCommonArgs(scanCmd)
	AddPlaceholderArgs(scanCmd)

	return scanCmd
}
