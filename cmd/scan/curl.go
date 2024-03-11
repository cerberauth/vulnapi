package scan

import (
	"log"
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/spf13/cobra"
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
			url = args[0]

			httpHeader := http.Header{}
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				httpHeader.Add(parts[0], strings.TrimLeft(parts[1], " "))
			}

			var httpCookies []http.Cookie
			for _, c := range cookies {
				parts := strings.SplitN(c, ":", 2)
				httpCookies = append(httpCookies, http.Cookie{
					Name:  parts[0],
					Value: parts[1],
				})
			}

			scan, err := scan.NewURLScan(method, url, httpHeader, httpCookies, nil)
			if err != nil {
				log.Fatal(err)
			}

			if reporter, _, err = scan.WithAllScans().Execute(); err != nil {
				log.Fatal(err)
			}
		},
	}

	scanCmd.PersistentFlags().StringVarP(&method, "request", "X", "GET", "Specify request method to use")
	scanCmd.PersistentFlags().StringArrayVarP(&headers, "header", "H", nil, "Pass custom header(s) to target API")
	scanCmd.PersistentFlags().StringArrayVarP(&cookies, "cookie", "b", nil, "Send cookies from string")

	// The following flags are not implemented yet
	scanCmd.PersistentFlags().StringVarP(&placeholderString, "data", "d", "", "HTTP POST data")
	scanCmd.PersistentFlags().BoolVarP(&placeholderBool, "fail", "f", false, "Fail silently (no output at all) on HTTP errors")
	scanCmd.PersistentFlags().BoolVarP(&placeholderBool, "include", "i", false, "Include protocol headers in the output")
	scanCmd.PersistentFlags().BoolVarP(&placeholderBool, "remote-name", "O", false, "Write output to a file named as the remote file")
	scanCmd.PersistentFlags().BoolVarP(&placeholderBool, "silent", "s", false, "Run in silent mode")
	scanCmd.PersistentFlags().StringVarP(&placeholderString, "upload-file", "T", "", "Transfer file to target API")
	scanCmd.PersistentFlags().StringVarP(&placeholderString, "user", "u", "", "Specify the user name and password to use for server authentication")
	scanCmd.PersistentFlags().StringVarP(&placeholderString, "user-agent", "A", "", "User-Agent to send to server")

	return scanCmd
}
