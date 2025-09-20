package report

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/stretchr/testify/assert"
)

func TestGetFilteredFailedIssueReports(t *testing.T) {
	// Create a reporter with mixed severity issues
	reporter := NewReporter()
	operation := operation.MustNewOperation("GET", "http://example.com/api", nil, nil)
	scanReport := NewScanReport("test", "Test Scan", operation)

	// Add issues with different severities
	highSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 8.5},
		Issue: Issue{
			Name: "High Severity Issue",
		},
		Status: IssueReportStatusFailed,
	}

	mediumSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 5.0},
		Issue: Issue{
			Name: "Medium Severity Issue",
		},
		Status: IssueReportStatusFailed,
	}

	lowSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 2.0},
		Issue: Issue{
			Name: "Low Severity Issue",
		},
		Status: IssueReportStatusFailed,
	}

	passedIssue := &IssueReport{
		CVSS: CVSSScore{Score: 1.0},
		Issue: Issue{
			Name: "Passed Issue",
		},
		Status: IssueReportStatusPassed,
	}

	scanReport.AddIssueReport(highSeverityIssue)
	scanReport.AddIssueReport(mediumSeverityIssue)
	scanReport.AddIssueReport(lowSeverityIssue)
	scanReport.AddIssueReport(passedIssue)
	reporter.AddReport(scanReport)

	// Test filtering with threshold 6.0 (should include only high severity)
	filteredReports := reporter.GetFilteredFailedIssueReports(6.0)
	assert.Len(t, filteredReports, 1)
	assert.Equal(t, "High Severity Issue", filteredReports[0].Issue.Name)
	assert.Equal(t, 8.5, filteredReports[0].CVSS.Score)

	// Test filtering with threshold 4.0 (should include high and medium)
	filteredReports = reporter.GetFilteredFailedIssueReports(4.0)
	assert.Len(t, filteredReports, 2)

	// Test filtering with threshold 0.0 (should include all failed issues)
	filteredReports = reporter.GetFilteredFailedIssueReports(0.0)
	assert.Len(t, filteredReports, 3) // Only failed issues, not passed ones
}

func TestGetFilteredScanReports(t *testing.T) {
	reporter := NewReporter()
	operation := operation.MustNewOperation("GET", "http://example.com/api", nil, nil)
	scanReport := NewScanReport("test", "Test Scan", operation)

	// Add a high severity failed issue
	highSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 8.5},
		Issue: Issue{
			Name: "High Severity Issue",
		},
		Status: IssueReportStatusFailed,
	}

	// Add a low severity failed issue
	lowSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 2.0},
		Issue: Issue{
			Name: "Low Severity Issue",
		},
		Status: IssueReportStatusFailed,
	}

	// Add a passed issue (should always be included)
	passedIssue := &IssueReport{
		CVSS: CVSSScore{Score: 1.0},
		Issue: Issue{
			Name: "Passed Issue",
		},
		Status: IssueReportStatusPassed,
	}

	scanReport.AddIssueReport(highSeverityIssue)
	scanReport.AddIssueReport(lowSeverityIssue)
	scanReport.AddIssueReport(passedIssue)
	reporter.AddReport(scanReport)

	// Test filtering with threshold 6.0
	filteredScanReports := reporter.GetFilteredScanReports(6.0)
	assert.Len(t, filteredScanReports, 1)
	
	filteredScanReport := filteredScanReports[0]
	assert.Equal(t, "test", filteredScanReport.ID)
	assert.Len(t, filteredScanReport.Issues, 2) // High severity + passed issue

	// Verify the correct issues are included
	issueNames := make([]string, len(filteredScanReport.Issues))
	for i, issue := range filteredScanReport.Issues {
		issueNames[i] = issue.Issue.Name
	}
	assert.Contains(t, issueNames, "High Severity Issue")
	assert.Contains(t, issueNames, "Passed Issue")
	assert.NotContains(t, issueNames, "Low Severity Issue")
}

func TestScanReportGetFilteredByThreshold(t *testing.T) {
	operation := operation.MustNewOperation("GET", "http://example.com/api", nil, nil)
	scanReport := NewScanReport("test", "Test Scan", operation)

	// Add issues with different severities and statuses
	highSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 8.5},
		Issue: Issue{Name: "High Severity Issue"},
		Status: IssueReportStatusFailed,
	}

	lowSeverityIssue := &IssueReport{
		CVSS: CVSSScore{Score: 2.0},
		Issue: Issue{Name: "Low Severity Issue"},
		Status: IssueReportStatusFailed,
	}

	passedIssue := &IssueReport{
		CVSS: CVSSScore{Score: 1.0},
		Issue: Issue{Name: "Passed Issue"},
		Status: IssueReportStatusPassed,
	}

	scanReport.AddIssueReport(highSeverityIssue)
	scanReport.AddIssueReport(lowSeverityIssue)
	scanReport.AddIssueReport(passedIssue)

	// Test with threshold 6.0
	filteredReport := scanReport.GetFilteredByThreshold(6.0)
	assert.NotNil(t, filteredReport)
	assert.Equal(t, "test", filteredReport.ID)
	assert.Len(t, filteredReport.Issues, 2) // High severity + passed

	// Test with very high threshold (should still include passed issues)
	filteredReport = scanReport.GetFilteredByThreshold(10.0)
	assert.NotNil(t, filteredReport)
	assert.Len(t, filteredReport.Issues, 1) // Only passed issue

	// Test with scan report that has only low severity issues
	scanReportLowOnly := NewScanReport("low", "Low Only", operation)
	scanReportLowOnly.AddIssueReport(lowSeverityIssue)
	
	filteredReport = scanReportLowOnly.GetFilteredByThreshold(6.0)
	assert.Nil(t, filteredReport) // Should return nil when no issues meet threshold
}