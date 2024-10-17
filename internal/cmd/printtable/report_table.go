package printtable

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cerberauth/vulnapi/report"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type ScanIssueReport struct {
	OperationMethod string `json:"method"`
	OperationPath   string `json:"path"`

	Issue *report.IssueReport `json:"issue"`
}

type SortByPathAndSeverity []*ScanIssueReport

func (a SortByPathAndSeverity) Len() int      { return len(a) }
func (a SortByPathAndSeverity) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a SortByPathAndSeverity) Less(i, j int) bool {
	if a[i].OperationPath == a[j].OperationPath {
		if a[i].OperationMethod == a[j].OperationMethod {
			return a[i].Issue.CVSS.Score > a[j].Issue.CVSS.Score
		}

		return a[i].OperationMethod < a[j].OperationMethod
	}

	return a[i].OperationPath < a[j].OperationPath
}

func NewScanIssueReports(r *report.ScanReport) []*ScanIssueReport {
	reports := r.GetFailedIssueReports()
	issues := make([]*ScanIssueReport, 0, len(reports))
	for _, ir := range reports {
		issues = append(issues, &ScanIssueReport{
			OperationMethod: ir.Operation.Method,
			OperationPath:   ir.Operation.URL.Path,

			Issue: ir,
		})
	}

	return issues
}

func NewFullScanIssueReports(reports []*report.ScanReport) []*ScanIssueReport {
	vulns := make([]*ScanIssueReport, 0)
	for _, r := range reports {
		vulns = append(vulns, NewScanIssueReports(r)...)
	}

	sort.Sort(SortByPathAndSeverity(vulns))

	return vulns
}

func severityTableColor(v *report.IssueReport) int {
	switch {
	case v.IsLowRiskSeverity() || v.IsInfoRiskSeverity():
		return tablewriter.BgBlueColor
	case v.IsMediumRiskSeverity():
		return tablewriter.BgYellowColor
	case v.IsHighRiskSeverity():
		return tablewriter.BgRedColor
	case v.IsCriticalRiskSeverity():
		return tablewriter.BgHiRedColor
	}

	return tablewriter.BgWhiteColor
}

func DisplayReportSummaryTable(r *report.Reporter) {
	if r == nil || len(r.GetScanReports()) == 0 {
		return
	}

	fmt.Println()
	headers := []string{"Status", "Scans Number"}
	table := CreateTable(headers)

	tableColors := make([]tablewriter.Colors, len(headers))
	tableColors[0] = tablewriter.Colors{tablewriter.Bold}
	tableColors[1] = tablewriter.Colors{tablewriter.Bold}

	statusCaser := cases.Title(language.English)
	for _, status := range report.IssueReportStatuses {
		scansNumber := len(r.GetReportsByIssueStatus(status))

		row := []string{
			statusCaser.String(strings.ToLower(status.String())),
			fmt.Sprintf("%d", scansNumber),
		}

		table.Rich(row, tableColors)
	}

	table.Render()
	fmt.Println()
}

func DisplayReportTable(r *report.Reporter) {
	if r == nil || !r.HasIssue() {
		return
	}

	headers := []string{"Operation", "Risk Level", "CVSS 4.0 Score", "OWASP", "Issue"}
	table := CreateTable(headers)

	IssueReports := NewFullScanIssueReports(r.GetScanReports())
	for _, issueReport := range IssueReports {
		row := []string{
			fmt.Sprintf("%s %s", issueReport.OperationMethod, issueReport.OperationPath),
			issueReport.Issue.SeverityLevelString(),
			fmt.Sprintf("%.1f", issueReport.Issue.CVSS.Score),
			string(issueReport.Issue.Classifications.OWASP),
			issueReport.Issue.Name,
		}

		tableColors := make([]tablewriter.Colors, len(headers))
		for i := range tableColors {
			if i == 1 {
				tableColors[i] = tablewriter.Colors{tablewriter.Bold, severityTableColor(issueReport.Issue)}
			} else {
				tableColors[i] = tablewriter.Colors{}
			}
		}

		table.Rich(row, tableColors)
	}

	errors := r.GetErrors()
	if len(errors) > 0 {
		fmt.Println()
		fmt.Println("Errors:")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	table.Render()
	fmt.Println()
}
