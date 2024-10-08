package report_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestReporter_NoHasHighRiskOrHigherSeverityVulnerability_WhenNoReport(t *testing.T) {
	reporter := report.NewReporter()
	assert.False(t, reporter.HasHighRiskOrHigherSeverityIssue())
}

func TestReporter_NoHasVulnerability_WhenNoFailedReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Pass()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.False(t, reporter.HasIssue())
}

func TestReporter_HasVulnerability_WhenFailedReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasIssue())
}

func TestReporters_HasHighRiskOrHigherSeverityVulnerability_WhenLowRiskReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 0.1,
		},
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.False(t, reporter.HasHighRiskOrHigherSeverityIssue())
}

func TestReporters_HasHighRiskOrHigherSeverityVulnerability_WhenHighRiskReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 8,
		},
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHighRiskOrHigherSeverityIssue())
}

func TestReporters_HasHighRiskOrHigherSeverityVulnerability_WhenCriticalRiskReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 9.8,
		},
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHighRiskOrHigherSeverityIssue())
}

func TestReporter_HasHigherThanSeverityThresholdIssue_WhenNoReports(t *testing.T) {
	reporter := report.NewReporter()
	assert.False(t, reporter.HasHigherThanSeverityThresholdIssue(5.0))
}

func TestReporter_HasHigherThanSeverityThresholdIssue_WhenBelowThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 4.0,
		},
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.False(t, reporter.HasHigherThanSeverityThresholdIssue(5.0))
}

func TestReporter_HasHigherThanSeverityThresholdIssue_WhenAtThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 5.0,
		},
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHigherThanSeverityThresholdIssue(5.0))
}

func TestReporter_HasHigherThanSeverityThresholdIssue_WhenAboveThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 7.0,
		},
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHigherThanSeverityThresholdIssue(5.0))
}

func TestReporter_GetReportsByIssueStatus_NoReports(t *testing.T) {
	reporter := report.NewReporter()
	reports := reporter.GetReportsByIssueStatus(report.IssueReportStatusFailed)
	assert.Empty(t, reports)
}

func TestReporter_GetReportsByIssueStatus_NoMatchingStatus(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Pass()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	reports := reporter.GetReportsByIssueStatus(report.IssueReportStatusFailed)
	assert.Empty(t, reports)
}

func TestReporter_GetReportsByIssueStatus_MatchingStatus(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	reports := reporter.GetReportsByIssueStatus(report.IssueReportStatusFailed)
	assert.NotEmpty(t, reports)
	assert.Equal(t, 1, len(reports))
	assert.Equal(t, "id", reports[0].ID)
}

func TestReporter_GetReportsByIssueStatus_MultipleReports(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr1 := report.NewScanReport("id1", "test1", operation)
	issue1 := report.Issue{
		Name: "test1",
	}
	IssueReport1 := report.NewIssueReport(issue1).Fail()
	sr1.AddIssueReport(IssueReport1)
	reporter.AddReport(sr1)

	sr2 := report.NewScanReport("id2", "test2", operation)
	issue2 := report.Issue{
		Name: "test2",
	}
	IssueReport2 := report.NewIssueReport(issue2).Fail()
	sr2.AddIssueReport(IssueReport2)
	reporter.AddReport(sr2)

	reports := reporter.GetReportsByIssueStatus(report.IssueReportStatusFailed)
	assert.NotEmpty(t, reports)
	assert.Equal(t, 2, len(reports))
	assert.Equal(t, "id1", reports[0].ID)
	assert.Equal(t, "id2", reports[1].ID)
}
