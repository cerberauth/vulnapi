package report

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
)

type IssueReportStatus string

func (vrs IssueReportStatus) String() string {
	return string(vrs)
}

const (
	IssueReportStatusPassed  IssueReportStatus = "passed"
	IssueReportStatusFailed  IssueReportStatus = "failed"
	IssueReportStatusSkipped IssueReportStatus = "skipped"
	IssueReportStatusNone    IssueReportStatus = "none"
)

var IssueReportStatuses = []IssueReportStatus{
	IssueReportStatusPassed,
	IssueReportStatusFailed,
	IssueReportStatusSkipped,
	IssueReportStatusNone,
}

type IssueReport struct {
	Issue  `json:",inline" yaml:",inline"`
	Status IssueReportStatus `json:"status" yaml:"status"`

	Operation      *operation.Operation `json:"-" yaml:"-"`
	SecurityScheme auth.SecurityScheme  `json:"-" yaml:"-"`
}

func NewIssueReport(issue Issue) *IssueReport {
	return &IssueReport{
		Issue:  issue,
		Status: IssueReportStatusNone,
	}
}

func (vr *IssueReport) WithOperation(operation *operation.Operation) *IssueReport {
	vr.Operation = operation
	return vr
}

func (vr *IssueReport) WithSecurityScheme(ss auth.SecurityScheme) *IssueReport {
	vr.SecurityScheme = ss
	return vr
}

func (vr *IssueReport) WithStatus(status IssueReportStatus) *IssueReport {
	vr.Status = status
	return vr
}

func (vr *IssueReport) WithBooleanStatus(status bool) *IssueReport {
	if status {
		return vr.Pass()
	}
	return vr.Fail()
}

func (vr *IssueReport) Fail() *IssueReport {
	vr.Status = IssueReportStatusFailed
	return vr
}

func (vr *IssueReport) HasFailed() bool {
	return vr.Status == IssueReportStatusFailed
}

func (vr *IssueReport) Pass() *IssueReport {
	vr.Status = IssueReportStatusPassed
	return vr
}

func (vr *IssueReport) HasPassed() bool {
	return vr.Status == IssueReportStatusPassed
}

func (vr *IssueReport) Skip() *IssueReport {
	vr.Status = IssueReportStatusSkipped
	return vr
}

func (vr *IssueReport) HasBeenSkipped() bool {
	return vr.Status == IssueReportStatusSkipped
}

func (vr *IssueReport) IsInfoRiskSeverity() bool {
	return vr.CVSS.Score == 0
}

func (vr *IssueReport) IsLowRiskSeverity() bool {
	return vr.CVSS.Score < 4 && vr.CVSS.Score > 0
}

func (vr *IssueReport) IsMediumRiskSeverity() bool {
	return vr.CVSS.Score > 4 && vr.CVSS.Score < 7
}

func (vr *IssueReport) IsHighRiskSeverity() bool {
	return vr.CVSS.Score > 7 && vr.CVSS.Score < 9
}

func (vr *IssueReport) IsCriticalRiskSeverity() bool {
	return vr.CVSS.Score > 9
}

func (vr *IssueReport) String() string {
	return fmt.Sprintf("[%s] %s", vr.SeverityLevelString(), vr.Name)
}

func (vr *IssueReport) SeverityLevelString() string {
	switch {
	case vr.IsCriticalRiskSeverity():
		return "Critical"
	case vr.IsHighRiskSeverity():
		return "High"
	case vr.IsMediumRiskSeverity():
		return "Medium"
	case vr.IsLowRiskSeverity():
		return "Low"
	case vr.IsInfoRiskSeverity():
		return "Info"
	default:
		return "None"
	}
}

func (vr *IssueReport) Clone() *IssueReport {
	return NewIssueReport(vr.Issue).WithOperation(vr.Operation).WithSecurityScheme(vr.SecurityScheme).WithStatus(vr.Status)
}
