package scan

import (
	"log"
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var (
	url     string
	method  string
	headers []string
	cookies []string

	placeholderString string
	placeholderBool   bool
)

func NewCURLScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "curl [URL]",
		Short: "URL Scan in CURL style",
		Args:  cobra.ExactArgs(1),
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/curl")
			url = args[0]

			httpHeader := http.Header{}
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				httpHeader.Add(parts[0], strings.TrimLeft(parts[1], " "))
			}

			var httpCookies []*http.Cookie
			for _, c := range cookies {
				parts := strings.SplitN(c, ":", 2)
				httpCookies = append(httpCookies, &http.Cookie{
					Name:  parts[0],
					Value: parts[1],
				})
			}

			analyticsx.TrackEvent(ctx, tracer, "Scan CURL", []attribute.KeyValue{
				attribute.String("method", method),
			})
			s, err := scan.NewURLScan(method, url, httpHeader, httpCookies, nil)
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

	scanCmd.Flags().StringVarP(&method, "request", "X", "GET", "Specify request method to use")
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
