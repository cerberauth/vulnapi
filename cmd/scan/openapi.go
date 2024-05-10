package scan

import (
	"log"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func NewOpenAPIScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "openapi [OpenAPIPAth]",
		Short: "Full OpenAPI operations scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/openapi")
			openapiUrlOrPath := args[0]

			openapi, err := openapi.LoadOpenAPI(ctx, openapiUrlOrPath)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			if err := openapi.Validate(ctx); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			var validToken *string
			if isStdinOpen() {
				validToken = readStdin()
			}

			analyticsx.TrackEvent(ctx, tracer, "Scan OpenAPI", []attribute.KeyValue{})
			client := NewHTTPClientFromArgs(rate, proxy, headers, cookies)
			s, err := scan.NewOpenAPIScan(openapi, validToken, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			s.WithAllVulnsScans().WithAllBestPracticesScans().WithAllOpenAPIDiscoverScans()
			bar := newProgressBar(len(s.GetOperationsScans()))

			if reporter, _, err = s.Execute(func(operationScan *scan.OperationScan) {
				bar.Add(1)
			}); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}
		},
	}

	scanCmd.Flags().StringVarP(&rate, "rate", "r", "10/s", "Specify the transfer rate")
	scanCmd.Flags().StringVarP(&proxy, "proxy", "x", "", "Use the specified HTTP proxy")

	return scanCmd
}
