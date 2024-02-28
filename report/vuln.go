package report

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/request"
)

type VulnerabilityReport struct {
	SeverityLevel float64 // https://nvd.nist.gov/vuln-metrics/cvss
	Name          string
	Description   string

	Operation *request.Operation
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
	return fmt.Sprintf("[%s][%s] %s %s: %s", vr.SeverityLevelString(), vr.Name, vr.Operation.Method, vr.Operation.Url, vr.Description)
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
	} else {
		return "None"
	}
}
