package printtable

import (
	"fmt"
	"net/url"
	"sort"

	"github.com/cerberauth/vulnapi/report"
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
			return a[i].Vuln.Issue.CVSS.Score > a[j].Vuln.Issue.CVSS.Score
		}

		return a[i].OperationMethod < a[j].OperationMethod
	}

	return a[i].OperationPath < a[j].OperationPath
}

func NewScanVulnerabilityReports(r *report.Report) []*ScanVulnerabilityReport {
	vulnReports := r.GetFailedVulnerabilityReports()
	vulns := make([]*ScanVulnerabilityReport, 0, len(vulnReports))
	for _, vulnReport := range vulnReports {
		url, urlErr := url.Parse(r.Operation.URL)
		if urlErr != nil {
			continue
		}

		vulns = append(vulns, &ScanVulnerabilityReport{
			OperationMethod: r.Operation.Method,
			OperationPath:   url.Path,

			Vuln: vulnReport,
		})
	}

	return vulns
}

func NewFullScanVulnerabilityReports(reports []*report.Report) []*ScanVulnerabilityReport {
	vulns := make([]*ScanVulnerabilityReport, 0)
	for _, r := range reports {
		vulns = append(vulns, NewScanVulnerabilityReports(r)...)
	}

	sort.Sort(SortByPathAndSeverity(vulns))

	return vulns
}

func severityTableColor(v *report.VulnerabilityReport) int {
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
	if r == nil || len(r.GetReports()) == 0 {
		return
	}

	fmt.Println()
	headers := []string{"Status", "Scans Number"}
	table := CreateTable(headers)

	tableColors := make([]tablewriter.Colors, len(headers))
	tableColors[0] = tablewriter.Colors{tablewriter.Bold}
	tableColors[1] = tablewriter.Colors{tablewriter.Bold}

	for _, status := range report.VulnerabilityReportStatuses {
		scansNumber := len(r.GetReportsByVulnerabilityStatus(status))

		row := []string{
			status.String(),
			fmt.Sprintf("%d", scansNumber),
		}

		table.Rich(row, tableColors)
	}

	table.Render()
	fmt.Println()
}

func DisplayReportTable(r *report.Reporter) {
	if r == nil || !r.HasVulnerability() {
		return
	}

	headers := []string{"Operation", "Risk Level", "CVSS 4.0 Score", "OWASP", "Vulnerability"}
	table := CreateTable(headers)

	vulnerabilityReports := NewFullScanVulnerabilityReports(r.GetReports())
	for _, vulnReport := range vulnerabilityReports {
		row := []string{
			fmt.Sprintf("%s %s", vulnReport.OperationMethod, vulnReport.OperationPath),
			vulnReport.Vuln.SeverityLevelString(),
			fmt.Sprintf("%.1f", vulnReport.Vuln.Issue.CVSS.Score),
			string(vulnReport.Vuln.Classifications.OWASP),
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
