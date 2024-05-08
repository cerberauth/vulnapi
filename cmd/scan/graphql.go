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
		Short: "Full GraphQL scan",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/graphql")
			graphqlEndpoint := args[0]

			analyticsx.TrackEvent(ctx, tracer, "Scan GraphQL", []attribute.KeyValue{})
			client := NewHTTPClientFromArgs(headers, cookies)
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

	scanCmd.Flags().StringArrayVarP(&headers, "header", "H", nil, "Pass custom header(s) to target API")
	scanCmd.Flags().StringArrayVarP(&cookies, "cookie", "b", nil, "Send cookies from string")

	// The following flags are not implemented yet
	scanCmd.Flags().StringVarP(&placeholderString, "data", "d", "", "HTTP POST data")
	scanCmd.Flags().BoolVarP(&placeholderBool, "fail", "f", false, "Fail silently (no output at all) on HTTP errors")
	scanCmd.Flags().BoolVarP(&placeholderBool, "include", "i", false, "Include protocol headers in the output")
	scanCmd.Flags().BoolVarP(&placeholderBool, "remote-name", "O", false, "Write output to a file named as the remote file")
	scanCmd.Flags().BoolVarP(&placeholderBool, "silent", "s", false, "Run in silent mode")
	scanCmd.Flags().StringVarP(&placeholderString, "upload-file", "T", "", "Transfer file to target API")
	scanCmd.Flags().StringVarP(&placeholderString, "user", "u", "", "Specify the user name and password to use for server authentication")
	scanCmd.Flags().StringVarP(&placeholderString, "user-agent", "A", "", "User-Agent to send to server")

	return scanCmd
}
