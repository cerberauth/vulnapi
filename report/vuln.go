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
)

type VulnerabilityReport struct {
	SeverityLevel float64 `json:"severity"` // TODO: Follow https://www.first.org/cvss/specification-document

	OWASP2023Category string `json:"owasp_2023_category"`

	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`

	Operation      *request.Operation  `json:"operation"`
	SecurityScheme auth.SecurityScheme `json:"security_scheme"`

	Status VulnerabilityReportStatus `json:"status"`
}

func NewVulnerabilityReport(severityLevel float64, owasp2023Category, id, name, url string) *VulnerabilityReport {
	return &VulnerabilityReport{
		SeverityLevel:     severityLevel,
		OWASP2023Category: owasp2023Category,
		ID:                id,
		Name:              name,
		URL:               url,
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
		vr.Status = VulnerabilityReportStatusPass
	} else {
		vr.Status = VulnerabilityReportStatusFail
	}
	return vr
}

func (vr *VulnerabilityReport) Fail() *VulnerabilityReport {
	vr.Status = VulnerabilityReportStatusFail
	return vr
}

func (vr *VulnerabilityReport) Pass() *VulnerabilityReport {
	vr.Status = VulnerabilityReportStatusPass
	return vr
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
