package report

import "fmt"

type VulnerabilityReport struct {
	SeverityLevel float64 // https://nvd.nist.gov/vuln-metrics/cvss
	Name          string
	Description   string
	Url           *string
}

func (vr *VulnerabilityReport) IsLowRiskSeverity() bool {
	return vr.SeverityLevel < 4
}

func (vr *VulnerabilityReport) IsMediumRiskSeverity() bool {
	return vr.SeverityLevel > 4 && vr.SeverityLevel < 7
}

func (vr *VulnerabilityReport) IsHighRiskSeverity() bool {
	return vr.SeverityLevel > 7
}

func (vr *VulnerabilityReport) String() string {
	return fmt.Sprintf("[%s] %s: %s", severyLevelString(vr.SeverityLevel), vr.Name, vr.Description)
}

func severyLevelString(severityLevel float64) string {
	if severityLevel >= 9 {
		return "critical"
	} else if severityLevel < 9 && severityLevel >= 7 {
		return "hight"
	} else if severityLevel < 7 && severityLevel >= 4 {
		return "medium"
	} else if severityLevel < 4 && severityLevel >= 0.1 {
		return "low"
	} else {
		return "none"
	}
}
