package scan

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
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
		PreRun: func(cmd *cobra.Command, args []string) {
			figure.NewColorFigure("VulnAPI", "", "cyan", true).Print()
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

			reporter, _, err := scan.WithAllVulnsScans().WithAllBestPracticesScans().Execute()
			if err != nil {
				log.Fatal(err)
			}

			var outputColor *color.Color
			var outputMessage string
			var outputStream *os.File
			if !reporter.HasVulnerability() {
				outputColor = color.New(color.FgGreen)
				outputMessage = "Congratulations! No issues were found."
				outputStream = os.Stdout
			} else if reporter.HasHighRiskSeverityVulnerability() {
				outputColor = color.New(color.FgRed)
				outputMessage = "Warning: Critical vulnerabilities detected!"
				outputStream = os.Stderr
			} else {
				outputColor = color.New(color.FgYellow)
				outputMessage = "Advice: There are some low-risk issues. It's advised to take a look."
				outputStream = os.Stderr
			}

			table := tablewriter.NewWriter(outputStream)
			table.SetHeader([]string{"Risk Level", "Vulnerability", "Description"})

			for _, v := range reporter.GetVulnerabilityReports() {
				var lineColor int
				if v.IsLowRiskSeverity() {
					lineColor = tablewriter.BgBlueColor
				} else if v.IsMediumRiskSeverity() {
					lineColor = tablewriter.FgYellowColor
				} else if v.IsHighRiskSeverity() {
					lineColor = tablewriter.FgRedColor
				}

				table.Rich(
					[]string{v.SeverityLevelString(), v.Name, v.Description},
					[]tablewriter.Colors{
						{tablewriter.Bold, lineColor},
						{tablewriter.Normal, lineColor},
						{tablewriter.Normal, tablewriter.FgWhiteColor}},
				)
			}

			table.Render()
			outputColor.Fprintln(outputStream, outputMessage)
		},
	}

	scanCmd.PersistentFlags().StringVarP(&method, "request", "X", "GET", "Specify request method to use")
	scanCmd.PersistentFlags().StringArrayVarP(&headers, "header", "H", nil, "Pass custom header(s) to target API")
	scanCmd.PersistentFlags().StringArrayVarP(&cookies, "cookie", "b", nil, "Send cookies from string")

	return scanCmd
}
