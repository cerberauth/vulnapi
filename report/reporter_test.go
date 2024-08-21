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
