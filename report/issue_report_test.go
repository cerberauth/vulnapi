package report_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewIssueScanReport(t *testing.T) {
	status := scan.IssueScanAttemptStatusFailed

	issueScanReport := report.NewIssueScanReport("scan-id", &status)

	assert.Equal(t, "scan-id", issueScanReport.ID)
	assert.Equal(t, status, *issueScanReport.Status)
}

func TestIssueScanReport_GetStatus(t *testing.T) {
	status := scan.IssueScanAttemptStatusPassed

	issueScanReport := report.NewIssueScanReport("scan-id", &status)

	assert.Equal(t, status, issueScanReport.GetStatus())
}

func TestIssueScanReport_HasFailed(t *testing.T) {
	status := scan.IssueScanAttemptStatusFailed

	issueScanReport := report.NewIssueScanReport("scan-id", &status)

	assert.True(t, issueScanReport.HasFailed())
}

func TestIssueScanReport_HasPassed(t *testing.T) {
	status := scan.IssueScanAttemptStatusPassed

	issueScanReport := report.NewIssueScanReport("scan-id", &status)

	assert.True(t, issueScanReport.HasPassed())
}

func TestNewIssueReport(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	assert.Equal(t, "id", vr.ID)
	assert.Equal(t, "Test Vulnerability", vr.Name)
	assert.Equal(t, "http://test.com", vr.URL)
	assert.Equal(t, 7.5, vr.CVSS.Score)
}

func TestIssueReport_WithOperation(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	operation := operation.MustNewOperation("GET", "/api/v1/", nil, nil)
	vr.WithOperation(operation)
	assert.Equal(t, "GET", vr.Operation.Method)
	assert.Equal(t, "/api/v1/", vr.Operation.URL.Path)
}

func TestIssueReport_WithSecurityScheme(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	value := jwt.FakeJWT
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", &value)
	vr.WithSecurityScheme(securityScheme)
	assert.Equal(t, jwt.FakeJWT, vr.SecurityScheme.GetValidValue())
}

func TestIssueReport_WithStatus(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.WithStatus(report.IssueReportStatusFailed)
	assert.Equal(t, report.IssueReportStatusFailed, vr.Status)
}

func TestIssueReport_WithBooleanStatus_WhenFalse(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.WithBooleanStatus(false)
	assert.Equal(t, report.IssueReportStatusFailed, vr.Status)
}

func TestIssueReport_WithBooleanStatus_WhenTrue(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.WithBooleanStatus(true)
	assert.Equal(t, report.IssueReportStatusPassed, vr.Status)
}

func TestIssueReport_Fail(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.Fail()
	assert.Equal(t, report.IssueReportStatusFailed, vr.Status)
}

func TestIssueReport_HasFailed(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.Fail()
	assert.True(t, vr.HasFailed())
}

func TestIssueReport_Pass(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.Pass()
	assert.Equal(t, report.IssueReportStatusPassed, vr.Status)
}

func TestIssueReport_HasPassed(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.Pass()
	assert.True(t, vr.HasPassed())
}

func TestIssueReport_Skip(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.Skip()
	assert.Equal(t, report.IssueReportStatusSkipped, vr.Status)
}

func TestIssueReport_HasBeenSkipped(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	vr.Skip()
	assert.True(t, vr.HasBeenSkipped())
}

func TestIssueReport_IsInfoRiskSeverity(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 0,
			},
		},
	}
	assert.True(t, vr.IsInfoRiskSeverity())
}

func TestIssueReport_IsLowRiskSeverity(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 3.5,
			},
		},
	}
	assert.True(t, vr.IsLowRiskSeverity())
}

func TestIssueReport_IsMediumRiskSeverity(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 5.5,
			},
		},
	}
	assert.True(t, vr.IsMediumRiskSeverity())
}

func TestIssueReport_IsHighRiskSeverity(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 8.5,
			},
		},
	}
	assert.True(t, vr.IsHighRiskSeverity())
}

func TestIssueReport_IsCriticalRiskSeverity(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			CVSS: report.CVSS{
				Score: 9.5,
			},
		},
	}
	assert.True(t, vr.IsCriticalRiskSeverity())
}

func TestIssueReport_WithScanAttempt(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	attempt := &scan.IssueScanAttempt{
		ID:     "scan-id",
		Status: scan.IssueScanAttemptStatusPassed,
	}
	vr.WithScanAttempt(attempt)
	assert.Equal(t, 1, len(vr.Scans))
	assert.Equal(t, "scan-id", vr.Scans[0].ID)
	assert.Equal(t, scan.IssueScanAttemptStatusPassed, *vr.Scans[0].Status)
}

func TestIssueReport_AddScanAttempt(t *testing.T) {
	issue := report.Issue{
		ID:   "id",
		Name: "Test Vulnerability",
		URL:  "http://test.com",
		CVSS: report.CVSS{
			Score: 7.5,
		},
	}
	vr := report.NewIssueReport(issue)
	attempt := &scan.IssueScanAttempt{
		ID:     "scan-id",
		Status: scan.IssueScanAttemptStatusFailed,
	}
	vr.AddScanAttempt(attempt)
	assert.Equal(t, 1, len(vr.Scans))
	assert.Equal(t, "scan-id", vr.Scans[0].ID)
	assert.Equal(t, scan.IssueScanAttemptStatusFailed, *vr.Scans[0].Status)
}

func TestIssueReport_String(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			Name: "Test Vulnerability",

			CVSS: report.CVSS{
				Score: 7.5,
			},
		},
	}
	expected := "[High] Test Vulnerability"
	assert.Equal(t, expected, vr.String())
}

func TestIssueReport_SeverityLevelString(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			CVSS: report.CVSS{},
		},
	}

	// Test case for severity level >= 9
	vr.Issue.CVSS.Score = 9.5
	assert.Equal(t, "Critical", vr.SeverityLevelString())

	// Test case for severity level < 9 and >= 7
	vr.Issue.CVSS.Score = 7.5
	assert.Equal(t, "High", vr.SeverityLevelString())

	// Test case for severity level < 7 and >= 4
	vr.Issue.CVSS.Score = 4.5
	assert.Equal(t, "Medium", vr.SeverityLevelString())

	// Test case for severity level < 4 and >= 0.1
	vr.Issue.CVSS.Score = 0.5
	assert.Equal(t, "Low", vr.SeverityLevelString())

	// Test case for severity level < 0.1
	vr.Issue.CVSS.Score = -1
	assert.Equal(t, "None", vr.SeverityLevelString())
}

func TestIssueReport_Clone(t *testing.T) {
	vr := &report.IssueReport{
		Issue: report.Issue{
			Name: "Test Vulnerability",
			URL:  "http://test.com",
			CVSS: report.CVSS{
				Score: 7.5,
			},
		},
	}
	clone := vr.Clone()
	assert.Equal(t, vr.ID, clone.ID)
	assert.Equal(t, vr.Name, clone.Name)
	assert.Equal(t, vr.URL, clone.URL)
	assert.Equal(t, vr.Issue.ID, clone.Issue.ID)
	assert.Equal(t, vr.Issue.Name, clone.Issue.Name)
	assert.Equal(t, vr.CVSS.Score, clone.CVSS.Score)
	assert.Equal(t, vr.Operation, clone.Operation)
	assert.Equal(t, vr.SecurityScheme, clone.SecurityScheme)
}
