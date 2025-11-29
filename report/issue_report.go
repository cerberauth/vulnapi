package report

import (
	"context"
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/x/telemetryx"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

type IssueScanReport struct {
	ID     string                       `json:"id" yaml:"id"`
	Status *scan.IssueScanAttemptStatus `json:"status" yaml:"status"`
}

func NewIssueScanReport(id string, status *scan.IssueScanAttemptStatus) *IssueScanReport {
	return &IssueScanReport{
		ID:     id,
		Status: status,
	}
}

func (issueScanReport *IssueScanReport) GetStatus() scan.IssueScanAttemptStatus {
	return *issueScanReport.Status
}

func (issueScanReport *IssueScanReport) HasFailed() bool {
	return *issueScanReport.Status == scan.IssueScanAttemptStatusFailed
}

func (issueScanReport *IssueScanReport) HasPassed() bool {
	return *issueScanReport.Status == scan.IssueScanAttemptStatusPassed
}

type IssueReport struct {
	Issue  `json:",inline" yaml:",inline"`
	Status IssueReportStatus `json:"status" yaml:"status"`

	Scans          []*IssueScanReport   `json:"scans" yaml:"scans"`
	Operation      *operation.Operation `json:"-" yaml:"-"`
	SecurityScheme *auth.SecurityScheme `json:"-" yaml:"-"`

	telemetryIssueStatusCounter metric.Int64Counter
}

const (
	otelIssueIdAttribute           = attribute.Key("issue_id")
	otelIssueReportStatusAttribute = attribute.Key("issue_report_status")
)

func NewIssueReport(issue Issue) *IssueReport {
	telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
	telemetryIssueStatusCounter, _ := telemetryMeter.Int64Counter("report.issue_status.counter")

	return &IssueReport{
		Issue:  issue,
		Status: IssueReportStatusNone,
		Scans:  []*IssueScanReport{},

		telemetryIssueStatusCounter: telemetryIssueStatusCounter,
	}
}

func (vr *IssueReport) WithOperation(operation *operation.Operation) *IssueReport {
	vr.Operation = operation
	return vr
}

func (vr *IssueReport) WithSecurityScheme(securityScheme *auth.SecurityScheme) *IssueReport {
	vr.SecurityScheme = securityScheme
	return vr
}

func (vr *IssueReport) WithStatus(status IssueReportStatus) *IssueReport {
	vr.Status = status
	vr.telemetryIssueStatusCounter.Add(context.Background(), 1, metric.WithAttributes(
		otelIssueIdAttribute.String(vr.ID),
		otelIssueReportStatusAttribute.String(vr.Status.String()),
	))
	return vr
}

func (vr *IssueReport) WithBooleanStatus(status bool) *IssueReport {
	if status {
		return vr.Pass()
	}
	return vr.Fail()
}

func (vr *IssueReport) Fail() *IssueReport {
	return vr.WithStatus(IssueReportStatusFailed)
}

func (vr *IssueReport) HasFailed() bool {
	return vr.Status == IssueReportStatusFailed
}

func (vr *IssueReport) Pass() *IssueReport {
	return vr.WithStatus(IssueReportStatusPassed)
}

func (vr *IssueReport) HasPassed() bool {
	return vr.Status == IssueReportStatusPassed
}

func (vr *IssueReport) Skip() *IssueReport {
	return vr.WithStatus(IssueReportStatusSkipped)
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

func (vr *IssueReport) WithScanAttempt(attempt *scan.IssueScanAttempt) *IssueReport {
	return vr.AddScanAttempt(attempt)
}

func (vr *IssueReport) AddScanAttempt(attempt *scan.IssueScanAttempt) *IssueReport {
	vr.Scans = append(vr.Scans, NewIssueScanReport(attempt.ID, &attempt.Status))
	return vr
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
