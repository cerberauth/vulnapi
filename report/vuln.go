package report

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
)

type VulnerabilityReportStatus string

const (
	VulnerabilityReportStatusPass VulnerabilityReportStatus = "pass"
	VulnerabilityReportStatusFail VulnerabilityReportStatus = "fail"
	VulnerabilityReportStatusSkip VulnerabilityReportStatus = "skip"
	VulnerabilityReportStatusNone VulnerabilityReportStatus = "none"
)

type VulnerabilityReport struct {
	Issue `json:",inline" yaml:",inline"`

	Operation      *request.Operation  `json:"operation" yaml:"operation"`
	SecurityScheme auth.SecurityScheme `json:"security_scheme" yaml:"security_scheme"`

	Status VulnerabilityReportStatus `json:"status" yaml:"status"`
}

func NewVulnerabilityReport(issue Issue) *VulnerabilityReport {
	return &VulnerabilityReport{
		Issue: issue,

		Status: VulnerabilityReportStatusNone,
	}
}

func (vr *VulnerabilityReport) WithOperation(operation *request.Operation) *VulnerabilityReport {
	vr.Operation = operation
	return vr
}

func (vr *VulnerabilityReport) WithSecurityScheme(ss auth.SecurityScheme) *VulnerabilityReport {
	vr.SecurityScheme = ss
	return vr
}

func (vr *VulnerabilityReport) WithStatus(status VulnerabilityReportStatus) *VulnerabilityReport {
	vr.Status = status
	return vr
}

func (vr *VulnerabilityReport) WithBooleanStatus(status bool) *VulnerabilityReport {
	if status {
		return vr.Pass()
	}
	return vr.Fail()
}

func (vr *VulnerabilityReport) Fail() *VulnerabilityReport {
	vr.Status = VulnerabilityReportStatusFail
	return vr
}

func (vr *VulnerabilityReport) HasFailed() bool {
	return vr.Status == VulnerabilityReportStatusFail
}

func (vr *VulnerabilityReport) Pass() *VulnerabilityReport {
	vr.Status = VulnerabilityReportStatusPass
	return vr
}

func (vr *VulnerabilityReport) HasPassed() bool {
	return vr.Status == VulnerabilityReportStatusPass
}

func (vr *VulnerabilityReport) Skip() *VulnerabilityReport {
	vr.Status = VulnerabilityReportStatusSkip
	return vr
}

func (vr *VulnerabilityReport) HasBeenSkipped() bool {
	return vr.Status == VulnerabilityReportStatusSkip
}

func (vr *VulnerabilityReport) IsInfoRiskSeverity() bool {
	return vr.CVSS.Score == 0
}

func (vr *VulnerabilityReport) IsLowRiskSeverity() bool {
	return vr.CVSS.Score < 4 && vr.CVSS.Score > 0
}

func (vr *VulnerabilityReport) IsMediumRiskSeverity() bool {
	return vr.CVSS.Score > 4 && vr.CVSS.Score < 7
}

func (vr *VulnerabilityReport) IsHighRiskSeverity() bool {
	return vr.CVSS.Score > 7 && vr.CVSS.Score < 9
}

func (vr *VulnerabilityReport) IsCriticalRiskSeverity() bool {
	return vr.CVSS.Score > 9
}

func (vr *VulnerabilityReport) String() string {
	return fmt.Sprintf("[%s] %s", vr.SeverityLevelString(), vr.Name)
}

func (vr *VulnerabilityReport) SeverityLevelString() string {
	if vr.IsCriticalRiskSeverity() {
		return "Critical"
	} else if vr.IsHighRiskSeverity() {
		return "High"
	} else if vr.IsMediumRiskSeverity() {
		return "Medium"
	} else if vr.IsLowRiskSeverity() {
		return "Low"
	} else if vr.IsInfoRiskSeverity() {
		return "Info"
	} else {
		return "None"
	}
}

func (vr *VulnerabilityReport) Clone() *VulnerabilityReport {
	return NewVulnerabilityReport(vr.Issue).WithOperation(vr.Operation).WithSecurityScheme(vr.SecurityScheme).WithStatus(vr.Status)
}
