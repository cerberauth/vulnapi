package scan

import (
	"fmt"
	"os"
	"sort"

	"github.com/cerberauth/vulnapi/report"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

type ScanVulnerabilityReport struct {
	OperationMethod string `json:"method"`
	OperationPath   string `json:"path"`

	Vuln *report.VulnerabilityReport `json:"vuln"`
}

type SortByPathAndSeverity []*ScanVulnerabilityReport

func (a SortByPathAndSeverity) Len() int      { return len(a) }
func (a SortByPathAndSeverity) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a SortByPathAndSeverity) Less(i, j int) bool {
	if a[i].OperationPath == a[j].OperationPath {
		if a[i].OperationMethod == a[j].OperationMethod {
			return a[i].Vuln.SeverityLevel > a[j].Vuln.SeverityLevel
		}

		return a[i].OperationMethod < a[j].OperationMethod
	}

	return a[i].OperationPath < a[j].OperationPath
}

func NewScanVulnerabilityReports(report *report.ScanReport) []*ScanVulnerabilityReport {
	vulns := make([]*ScanVulnerabilityReport, 0, len(report.GetVulnerabilityReports()))
	for _, vr := range report.GetVulnerabilityReports() {
		vulns = append(vulns, &ScanVulnerabilityReport{
			OperationMethod: report.Operation.Method,
			OperationPath:   report.Operation.Path,

			Vuln: vr,
		})
	}

	return vulns
}

func NewFullScanVulnerabilityReports(reports []*report.ScanReport) []*ScanVulnerabilityReport {
	vulns := make([]*ScanVulnerabilityReport, 0)
	for _, r := range reports {
		vulns = append(vulns, NewScanVulnerabilityReports(r)...)
	}

	sort.Sort(SortByPathAndSeverity(vulns))

	return vulns
}

func severityTableColor(v *report.VulnerabilityReport) int {
	if v.IsLowRiskSeverity() || v.IsInfoRiskSeverity() {
		return tablewriter.BgBlueColor
	} else if v.IsMediumRiskSeverity() {
		return tablewriter.BgYellowColor
	} else if v.IsHighRiskSeverity() {
		return tablewriter.BgRedColor
	}

	return tablewriter.BgWhiteColor
}

func DisplayReportTable(reporter *report.Reporter) {
	var outputColor *color.Color
	var outputMessage string
	var outputStream *os.File
	if !reporter.HasVulnerability() {
		outputColor = color.New(color.FgGreen)
		outputMessage = "Congratulations! No issues were found."
		outputStream = os.Stdout
	} else if reporter.HasHighRiskSeverityVulnerability() {
		outputColor = color.New(color.BgRed, color.FgWhite)
		outputMessage = "Warning: Critical vulnerabilities detected!"
		outputStream = os.Stderr
	} else {
		outputColor = color.New(color.BgYellow, color.FgBlack)
		outputMessage = "Advice: There are some low-risk issues. It's advised to take a look."
		outputStream = os.Stderr
	}

	fmt.Println()
	fmt.Println()
	outputColor.Fprintln(outputStream, outputMessage)
	fmt.Println()

	headers := []string{"Operation", "Risk Level", "OWASP", "Vulnerability"}

	table := tablewriter.NewWriter(outputStream)
	table.SetHeader(headers)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	vulnerabilityReports := NewFullScanVulnerabilityReports(reporter.GetReports())
	for _, vulnReport := range vulnerabilityReports {
		row := []string{
			fmt.Sprintf("%s %s", vulnReport.OperationMethod, vulnReport.OperationPath),
			vulnReport.Vuln.SeverityLevelString(),
			vulnReport.Vuln.OWASP2023Category,
			vulnReport.Vuln.Name,
		}

		tableColors := make([]tablewriter.Colors, len(headers))
		for i := range tableColors {
			if i == 1 {
				tableColors[i] = tablewriter.Colors{tablewriter.Bold, severityTableColor(vulnReport.Vuln)}
			} else {
				tableColors[i] = tablewriter.Colors{}
			}
		}

		table.Rich(row, tableColors)
	}

	table.Render()
}

func DisplayUnexpectedErrorMessage() {
	fmt.Println()
	fmt.Println("If you think that report is not accurate or if you have any suggestions for improvements, please open an issue at: https://github.com/cerberauth/vulnapi/issues/new.")
}
