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

			httpHeaders := http.Header{}
			for _, h := range headers {
				parts := strings.SplitN(h, ":", 2)
				httpHeaders.Add(parts[0], strings.TrimLeft(parts[1], " "))
			}

			var httpCookies []http.Cookie
			for _, c := range cookies {
				parts := strings.SplitN(c, ":", 2)
				httpCookies = append(httpCookies, http.Cookie{
					Name:  parts[0],
					Value: parts[1],
				})
			}

			scan, err := scan.NewURLScan(method, url, &httpHeaders, httpCookies, nil)
			if err != nil {
				log.Fatal(err)
			}

			rpr, _, err := scan.WithAllVulnsScans().Execute()
			if err != nil {
				log.Fatal(err)
			}

			if !rpr.HasVulnerability() {
				log.Println("Congratulations! No vulnerability has been discovered!")
			}

			for _, r := range rpr.GetVulnerabilityReports() {
				log.Fatalln(r)
			}
		},
	}

	scanCmd.PersistentFlags().StringVarP(&method, "request", "X", "GET", "Specify request method to use")
	scanCmd.PersistentFlags().StringArrayVarP(&headers, "header", "H", nil, "Pass custom header(s) to target API")
	scanCmd.PersistentFlags().StringArrayVarP(&cookies, "cookie", "b", nil, "Send cookies from string")

	return scanCmd
}
