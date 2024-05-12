package scan

import (
	"log"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var (
	curlUrl    string
	curlMethod string
)

func NewCURLScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "curl [URL]",
		Short: "CURL style Scan",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/curl")
			curlUrl = args[0]

			analyticsx.TrackEvent(ctx, tracer, "Scan CURL", []attribute.KeyValue{
				attribute.String("method", curlMethod),
			})
			client := NewHTTPClientFromArgs(rateLimit, proxy, headers, cookies)
			s, err := scan.NewURLScan(curlMethod, curlUrl, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			s.WithAllScans()
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
	scanCmd.Flags().StringVarP(&curlMethod, "request", "X", "GET", "Specify request method to use")

	return scanCmd
}
