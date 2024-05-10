package report

type Reporter struct {
	Reports []*ScanReport `json:"reports"`
}

func NewReporter() *Reporter {
	return &Reporter{
		Reports: []*ScanReport{},
	}
}

func (rr *Reporter) AddReport(r *ScanReport) {
	rr.Reports = append(rr.Reports, r)
}

func (rr *Reporter) GetReports() []*ScanReport {
	return rr.Reports
}

func (rr *Reporter) HasVulnerability() bool {
	for _, r := range rr.GetReports() {
		if r.HasFailedVulnerabilityReport() {
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
