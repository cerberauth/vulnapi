package report

import (
	"fmt"
)

type VulnerabilityReport struct {
	SeverityLevel float64 `json:"severity"` // TODO: Follow https://www.first.org/cvss/specification-document

	OWASP2023Category string `json:"owasp_2023_category"`

	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
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

func (vr *VulnerabilityReport) IsInfoRiskSeverity() bool {
	return vr.SeverityLevel == 0
}

func (vr *VulnerabilityReport) String() string {
	return fmt.Sprintf("[%s] %s", vr.SeverityLevelString(), vr.Name)
}

func (vr *VulnerabilityReport) SeverityLevelString() string {
	if vr.SeverityLevel >= 9 {
		return "Critical"
	} else if vr.SeverityLevel < 9 && vr.SeverityLevel >= 7 {
		return "High"
	} else if vr.SeverityLevel < 7 && vr.SeverityLevel >= 4 {
		return "Medium"
	} else if vr.SeverityLevel < 4 && vr.SeverityLevel >= 0.1 {
		return "Low"
	} else if vr.SeverityLevel == 0 {
		return "Info"
	} else {
		return "None"
	}
}
