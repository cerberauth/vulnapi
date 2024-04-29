package api

import (
	"time"

	"github.com/cerberauth/vulnapi/report"
)

type HTTPResponseVulnerability struct {
	SeverityLevel float64 `json:"severity"`
	Name          string  `json:"name"`
}

type HTTPResponseReport struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`

	Vulns []HTTPResponseVulnerability `json:"vulnerabilities"`
}

func formatVulnerabilitReport(vr *report.VulnerabilityReport) HTTPResponseVulnerability {
	return HTTPResponseVulnerability{
		SeverityLevel: vr.SeverityLevel,
		Name:          vr.Name,
	}
}

func formatVulnerabilities(vrs []*report.VulnerabilityReport) []HTTPResponseVulnerability {
	vulns := make([]HTTPResponseVulnerability, 0, len(vrs))
	for _, vr := range vrs {
		vulns = append(vulns, formatVulnerabilitReport(vr))
	}

	return vulns
}

func formatReport(report *report.ScanReport) HTTPResponseReport {
	return HTTPResponseReport{
		ID:        report.ID,
		Name:      report.Name,
		StartTime: report.StartTime,
		EndTime:   report.EndTime,

		Vulns: formatVulnerabilities(report.GetVulnerabilityReports()),
	}
}

func FormatReports(reports []*report.ScanReport) (responseReports []HTTPResponseReport) {
	for _, r := range reports {
		responseReports = append(responseReports, formatReport(r))
	}

	return responseReports
}
