package scan

import (
	"log"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/analyticsx"
	"github.com/schollz/progressbar/v3"
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
			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			s, err := scenario.NewGraphQLScan(graphqlEndpoint, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			var bar *progressbar.ProgressBar
			if !internalCmd.GetNoProgress() {
				bar = internalCmd.NewProgressBar(len(s.GetOperationsScans()))
				defer bar.Finish()
			}
			reporter, _, err := s.Execute(func(operationScan *scan.OperationScan) {
				if bar != nil {
					bar.Add(1)
				}
			}, internalCmd.GetIncludeScans(), internalCmd.GetExcludeScans())
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			internalCmd.TrackScanReport(ctx, tracer, reporter)
			internalCmd.PrintOrExportReport(internalCmd.GetOutputFormat(), internalCmd.GetOutputTransport(), reporter)
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	internalCmd.AddPlaceholderArgs(scanCmd)

	return scanCmd
}
