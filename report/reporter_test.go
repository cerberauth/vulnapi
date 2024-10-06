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
	assert.False(t, reporter.HasHighRiskOrHigherSeverityVulnerability())
}

func TestReporter_NoHasVulnerability_WhenNoFailedReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Pass()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.False(t, reporter.HasVulnerability())
}

func TestReporter_HasVulnerability_WhenFailedReport(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasVulnerability())
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
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.False(t, reporter.HasHighRiskOrHigherSeverityVulnerability())
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
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHighRiskOrHigherSeverityVulnerability())
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
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHighRiskOrHigherSeverityVulnerability())
}

func TestReporter_HasHigherThanSeverityThresholdVulnerability_WhenNoReports(t *testing.T) {
	reporter := report.NewReporter()
	assert.False(t, reporter.HasHigherThanSeverityThresholdVulnerability(5.0))
}

func TestReporter_HasHigherThanSeverityThresholdVulnerability_WhenBelowThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 4.0,
		},
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.False(t, reporter.HasHigherThanSeverityThresholdVulnerability(5.0))
}

func TestReporter_HasHigherThanSeverityThresholdVulnerability_WhenAtThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 5.0,
		},
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHigherThanSeverityThresholdVulnerability(5.0))
}

func TestReporter_HasHigherThanSeverityThresholdVulnerability_WhenAboveThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
		CVSS: report.CVSS{
			Score: 7.0,
		},
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	assert.True(t, reporter.HasHigherThanSeverityThresholdVulnerability(5.0))
}

func TestReporter_GetReportsByVulnerabilityStatus_NoReports(t *testing.T) {
	reporter := report.NewReporter()
	reports := reporter.GetReportsByVulnerabilityStatus(report.VulnerabilityReportStatusFailed)
	assert.Empty(t, reports)
}

func TestReporter_GetReportsByVulnerabilityStatus_NoMatchingStatus(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Pass()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	reports := reporter.GetReportsByVulnerabilityStatus(report.VulnerabilityReportStatusFailed)
	assert.Empty(t, reports)
}

func TestReporter_GetReportsByVulnerabilityStatus_MatchingStatus(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	reporter.AddReport(sr)

	reports := reporter.GetReportsByVulnerabilityStatus(report.VulnerabilityReportStatusFailed)
	assert.NotEmpty(t, reports)
	assert.Equal(t, 1, len(reports))
	assert.Equal(t, "id", reports[0].ID)
}

func TestReporter_GetReportsByVulnerabilityStatus_MultipleReports(t *testing.T) {
	reporter := report.NewReporter()
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr1 := report.NewScanReport("id1", "test1", operation)
	issue1 := report.Issue{
		Name: "test1",
	}
	vulnerabilityReport1 := report.NewVulnerabilityReport(issue1).Fail()
	sr1.AddVulnerabilityReport(vulnerabilityReport1)
	reporter.AddReport(sr1)

	sr2 := report.NewScanReport("id2", "test2", operation)
	issue2 := report.Issue{
		Name: "test2",
	}
	vulnerabilityReport2 := report.NewVulnerabilityReport(issue2).Fail()
	sr2.AddVulnerabilityReport(vulnerabilityReport2)
	reporter.AddReport(sr2)

	reports := reporter.GetReportsByVulnerabilityStatus(report.VulnerabilityReportStatusFailed)
	assert.NotEmpty(t, reports)
	assert.Equal(t, 2, len(reports))
	assert.Equal(t, "id1", reports[0].ID)
	assert.Equal(t, "id2", reports[1].ID)
}
