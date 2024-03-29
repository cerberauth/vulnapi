package scan

import (
	"fmt"
	"os"

	"github.com/cerberauth/vulnapi/report"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
)

var reporter *report.Reporter

func severityTableColor(v *report.VulnerabilityReport) int {
	if v.IsLowRiskSeverity() || v.IsInfoRiskSeverity() {
		return tablewriter.BgBlueColor
	} else if v.IsMediumRiskSeverity() {
		return tablewriter.FgYellowColor
	} else if v.IsHighRiskSeverity() {
		return tablewriter.FgRedColor
	}

	return tablewriter.BgWhiteColor
}

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan [type]",
		Short: "API Scan",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			figure.NewColorFigure("VulnAPI", "", "cyan", true).Print()
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if reporter == nil {
				return
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

			headers := []string{"Risk Level", "Vulnerability", "Description"}
			if cmd.Name() == "openapi" {
				headers = append(headers, "Operation")
			}

			table := tablewriter.NewWriter(outputStream)
			table.SetHeader(headers)

			for _, v := range reporter.GetVulnerabilityReports() {
				lineColor := severityTableColor(v)
				row := []string{v.SeverityLevelString(), v.Name, v.Description}
				if cmd.Name() == "openapi" {
					row = append(row, fmt.Sprintf("%s %s", v.Operation.Method, v.Operation.Request.URL.String()))
				}

				tableColors := make([]tablewriter.Colors, len(headers))
				for i := range tableColors {
					tableColors[i] = tablewriter.Colors{tablewriter.Bold, lineColor}
				}

				table.Rich(row, tableColors)
			}

			table.Render()
			outputColor.Fprintln(outputStream, outputMessage)
		},
	}
	scanCmd.AddCommand(NewCURLScanCmd())
	scanCmd.AddCommand(NewOpenAPIScanCmd())

	return scanCmd
}
