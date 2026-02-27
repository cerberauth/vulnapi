package cmd_test

import (
	"encoding/json"
	"net/http"
	"testing"

	cmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func createTestReporter() *report.Reporter {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/test", nil, nil)

	// Low severity issue (should be filtered out with threshold 5.0)
	sr1 := report.NewScanReport("id1", "test1", operation)
	issue1 := report.Issue{
		Name: "Low Severity Issue",
		CVSS: report.CVSS{
			Score: 2.0,
		},
	}
	issueReport1 := report.NewIssueReport(issue1).Fail()
	sr1.AddIssueReport(issueReport1)
	reporter.AddReport(sr1)

	// Medium severity issue (should be included with threshold 5.0)
	sr2 := report.NewScanReport("id2", "test2", operation)
	issue2 := report.Issue{
		Name: "Medium Severity Issue",
		CVSS: report.CVSS{
			Score: 5.0,
		},
	}
	issueReport2 := report.NewIssueReport(issue2).Fail()
	sr2.AddIssueReport(issueReport2)
	reporter.AddReport(sr2)

	// High severity issue (should be included with threshold 5.0)
	sr3 := report.NewScanReport("id3", "test3", operation)
	issue3 := report.Issue{
		Name: "High Severity Issue",
		CVSS: report.CVSS{
			Score: 8.0,
		},
	}
	issueReport3 := report.NewIssueReport(issue3).Fail()
	sr3.AddIssueReport(issueReport3)
	reporter.AddReport(sr3)

	// Passed issue (should always be included regardless of threshold)
	sr4 := report.NewScanReport("id4", "test4", operation)
	issue4 := report.Issue{
		Name: "Passed Issue",
		CVSS: report.CVSS{
			Score: 1.0,
		},
	}
	issueReport4 := report.NewIssueReport(issue4).Pass()
	sr4.AddIssueReport(issueReport4)
	reporter.AddReport(sr4)

	return reporter
}

func TestExportJSON_NoThreshold(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportJSON(reporter)
	assert.NoError(t, err)
	assert.NotEmpty(t, output)

	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should include all reports
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 4, len(reports))
}

func TestExportJSONWithThreshold_ZeroThreshold(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportJSONWithThreshold(reporter, 0.0)
	assert.NoError(t, err)
	assert.NotEmpty(t, output)

	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should include all reports (same as ExportJSON when threshold is 0)
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 4, len(reports))
}

func TestExportJSONWithThreshold_PositiveThreshold(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportJSONWithThreshold(reporter, 5.0)
	assert.NoError(t, err)
	assert.NotEmpty(t, output)

	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should include only filtered reports
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	
	// Should include: medium severity (5.0), high severity (8.0), and passed issue
	// Should exclude: low severity (2.0)
	assert.Equal(t, 3, len(reports))

	// Verify the correct issues are included
	var issueNames []string
	for _, report := range reports {
		reportMap := report.(map[string]interface{})
		issues := reportMap["issues"].([]interface{})
		for _, issue := range issues {
			issueMap := issue.(map[string]interface{})
			issueNames = append(issueNames, issueMap["name"].(string))
		}
	}

	assert.Contains(t, issueNames, "Medium Severity Issue")
	assert.Contains(t, issueNames, "High Severity Issue")
	assert.Contains(t, issueNames, "Passed Issue")
	assert.NotContains(t, issueNames, "Low Severity Issue")
}

func TestExportYAML_NoThreshold(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportYAML(reporter)
	assert.NoError(t, err)
	assert.NotEmpty(t, output)

	var result map[string]interface{}
	err = yaml.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should include all reports
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 4, len(reports))
}

func TestExportYAMLWithThreshold_ZeroThreshold(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportYAMLWithThreshold(reporter, 0.0)
	assert.NoError(t, err)
	assert.NotEmpty(t, output)

	var result map[string]interface{}
	err = yaml.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should include all reports (same as ExportYAML when threshold is 0)
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 4, len(reports))
}

func TestExportYAMLWithThreshold_PositiveThreshold(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportYAMLWithThreshold(reporter, 5.0)
	assert.NoError(t, err)
	assert.NotEmpty(t, output)

	var result map[string]interface{}
	err = yaml.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should include only filtered reports
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	
	// Should include: medium severity (5.0), high severity (8.0), and passed issue
	// Should exclude: low severity (2.0)
	assert.Equal(t, 3, len(reports))

	// Verify the correct issues are included
	var issueNames []string
	for _, report := range reports {
		reportMap := report.(map[string]interface{})
		issues := reportMap["issues"].([]interface{})
		for _, issue := range issues {
			issueMap := issue.(map[string]interface{})
			issueNames = append(issueNames, issueMap["name"].(string))
		}
	}

	assert.Contains(t, issueNames, "Medium Severity Issue")
	assert.Contains(t, issueNames, "High Severity Issue")
	assert.Contains(t, issueNames, "Passed Issue")
	assert.NotContains(t, issueNames, "Low Severity Issue")
}

func TestCreateFilteredReporter_EmptyReporter(t *testing.T) {
	reporter := report.NewReporter()
	
	// Use reflection to access the unexported function
	// For testing purposes, we'll test via the exported functions that use it
	output, err := cmd.ExportJSONWithThreshold(reporter, 5.0)
	assert.NoError(t, err)
	
	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 0, len(reports))
}

func TestCreateFilteredReporter_AllIssuesBelowThreshold(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/test", nil, nil)

	// Add only low severity issues
	sr1 := report.NewScanReport("id1", "test1", operation)
	issue1 := report.Issue{
		Name: "Low Severity Issue 1",
		CVSS: report.CVSS{
			Score: 2.0,
		},
	}
	issueReport1 := report.NewIssueReport(issue1).Fail()
	sr1.AddIssueReport(issueReport1)
	reporter.AddReport(sr1)

	sr2 := report.NewScanReport("id2", "test2", operation)
	issue2 := report.Issue{
		Name: "Low Severity Issue 2",
		CVSS: report.CVSS{
			Score: 3.0,
		},
	}
	issueReport2 := report.NewIssueReport(issue2).Fail()
	sr2.AddIssueReport(issueReport2)
	reporter.AddReport(sr2)

	output, err := cmd.ExportJSONWithThreshold(reporter, 5.0)
	assert.NoError(t, err)
	
	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Should have empty reports array since all issues are filtered out
	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 0, len(reports))
}

func TestCreateFilteredReporter_PreservesReporterMetadata(t *testing.T) {
	reporter := createTestReporter()
	
	output, err := cmd.ExportJSONWithThreshold(reporter, 5.0)
	assert.NoError(t, err)
	
	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	// Verify that reporter metadata is preserved
	assert.Equal(t, "https://schemas.cerberauth.com/vulnapi/draft/2024-10/report.schema.json", result["$schema"])
	assert.NotNil(t, result["options"])
}

func TestCreateFilteredScanReport_MixedIssueStatuses(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/test", nil, nil)

	sr := report.NewScanReport("id1", "test1", operation)
	
	// Failed issue below threshold (should be excluded)
	issue1 := report.Issue{
		Name: "Failed Low Severity",
		CVSS: report.CVSS{
			Score: 2.0,
		},
	}
	issueReport1 := report.NewIssueReport(issue1).Fail()
	sr.AddIssueReport(issueReport1)

	// Failed issue above threshold (should be included)
	issue2 := report.Issue{
		Name: "Failed High Severity",
		CVSS: report.CVSS{
			Score: 8.0,
		},
	}
	issueReport2 := report.NewIssueReport(issue2).Fail()
	sr.AddIssueReport(issueReport2)

	// Passed issue below threshold (should be included)
	issue3 := report.Issue{
		Name: "Passed Low Severity",
		CVSS: report.CVSS{
			Score: 1.0,
		},
	}
	issueReport3 := report.NewIssueReport(issue3).Pass()
	sr.AddIssueReport(issueReport3)

	// Skipped issue below threshold (should be included)
	issue4 := report.Issue{
		Name: "Skipped Low Severity",
		CVSS: report.CVSS{
			Score: 1.0,
		},
	}
	issueReport4 := report.NewIssueReport(issue4).Skip()
	sr.AddIssueReport(issueReport4)

	reporter.AddReport(sr)

	output, err := cmd.ExportJSONWithThreshold(reporter, 5.0)
	assert.NoError(t, err)
	
	var result map[string]interface{}
	err = json.Unmarshal(output, &result)
	assert.NoError(t, err)

	reports, ok := result["reports"].([]interface{})
	assert.True(t, ok)
	assert.Equal(t, 1, len(reports))

	// Verify the correct issues are included
	reportMap := reports[0].(map[string]interface{})
	issues := reportMap["issues"].([]interface{})
	assert.Equal(t, 3, len(issues))

	var issueNames []string
	for _, issue := range issues {
		issueMap := issue.(map[string]interface{})
		issueNames = append(issueNames, issueMap["name"].(string))
	}

	assert.Contains(t, issueNames, "Failed High Severity")
	assert.Contains(t, issueNames, "Passed Low Severity")
	assert.Contains(t, issueNames, "Skipped Low Severity")
	assert.NotContains(t, issueNames, "Failed Low Severity")
}