package scan

import (
	"sort"

	"github.com/cerberauth/vulnapi/report"
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
