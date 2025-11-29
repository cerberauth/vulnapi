package scan

import (
	"log"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/analytics"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/codes"
)

func NewCURLScanCmd() (scanCmd *cobra.Command) {
	var (
		curlMethod string
		curlData   string
	)

	scanCmd = &cobra.Command{
		Use:   "curl [URL]",
		Short: "CURL style Scan",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			if args[0] == "" {
				log.Fatal("URL is required")
			}

			ctx, span := tracer.Start(cmd.Context(), "Scan cURL")
			defer span.End()

			parsedUrl, err := url.Parse(args[0])
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}

			client, err := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}
			request.SetDefaultClient(client)

			s, err := scenario.NewURLScan(curlMethod, parsedUrl, curlData, client, &scan.ScanOptions{
				IncludeScans: internalCmd.GetIncludeScans(),
				ExcludeScans: internalCmd.GetExcludeScans(),
			})
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
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
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}

			analytics.TrackScanReport(ctx, reporter)
			err = internalCmd.PrintOrExportReport(internalCmd.GetReportFormat(), internalCmd.GetReportTransport(), reporter)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, err.Error())
				log.Fatal(err)
			}
		},
	}

	internalCmd.AddCommonArgs(scanCmd)
	internalCmd.AddPlaceholderArgs(scanCmd)
	scanCmd.Flags().StringVarP(&curlMethod, "request", "X", "GET", "Specify request method to use")
	scanCmd.Flags().StringVarP(&curlData, "data", "d", "", "HTTP POST data")

	return scanCmd
}
