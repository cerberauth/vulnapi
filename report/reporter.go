package report

type Reporter struct {
	reports []*ScanReport
}

func NewReporter() *Reporter {
	return &Reporter{
		reports: []*ScanReport{},
	}
}

func (rr *Reporter) AddReport(r *ScanReport) {
	rr.reports = append(rr.reports, r)
}

func (rr *Reporter) GetReports() []*ScanReport {
	return rr.reports
}

func (rr *Reporter) HasVulnerability() bool {
	for _, r := range rr.GetReports() {
		if r.HasVulnerabilityReport() {
			return true
		}
	}

	return false
}

func (rr *Reporter) GetVulnerabilityReports() []*VulnerabilityReport {
	var vrs []*VulnerabilityReport
	for _, r := range rr.GetReports() {
		vrs = append(vrs, r.GetVulnerabilityReports()...)
	}

	return vrs
}

func (rr *Reporter) HasHighRiskSeverityVulnerability() bool {
	for _, r := range rr.GetVulnerabilityReports() {
		if r.IsHighRiskSeverity() {
			return true
		}
	}

	return false
}
