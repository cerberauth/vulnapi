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

func (rr *Reporter) GetErrors() []error {
	var errors []error
	for _, r := range rr.GetReports() {
		errors = append(errors, r.GetErrors()...)
	}

	return errors
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

func (rr *Reporter) HasHighRiskOrHigherSeverityVulnerability() bool {
	for _, r := range rr.GetVulnerabilityReports() {
		if r.IsHighRiskSeverity() || r.IsCriticalRiskSeverity() {
			return true
		}
	}

	return false
}
