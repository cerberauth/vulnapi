package report_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	openapilib "github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewReporterWithCurl(t *testing.T) {
	method := http.MethodPost
	url := "http://localhost:8080/"
	data := map[string]string{"key": "value"}
	header := http.Header{"Content-Type": []string{"application/json"}}
	cookies := []*http.Cookie{{Name: "session_id", Value: "abc123"}}
	token := "abc123"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	securitySchemes := []auth.SecurityScheme{securityScheme}

	reportSecuritySchemes := []report.OperationSecurityScheme{
		{
			Type:   securityScheme.GetType(),
			Scheme: securityScheme.GetScheme(),
			In:     securityScheme.GetIn(),
			Name:   securityScheme.GetName(),
		},
	}

	reporter := report.NewReporterWithCurl(method, url, data, header, cookies, securitySchemes)

	assert.NotNil(t, reporter)
	assert.NotNil(t, reporter.Curl)
	assert.Equal(t, method, reporter.Curl.Method)
	assert.Equal(t, url, reporter.Curl.URL)
	assert.Equal(t, data, reporter.Curl.Data)
	assert.Equal(t, header, reporter.Curl.Header)
	assert.Equal(t, cookies, reporter.Curl.Cookies)
	assert.Equal(t, reportSecuritySchemes, reporter.Curl.SecuritySchemes)
	assert.Empty(t, reporter.ScanReports)
}

func TestNewReporterWithCurl_AddReport(t *testing.T) {
	method := http.MethodPost
	url := "http://localhost:8080/"
	data := map[string]string{"key": "value"}
	header := http.Header{"Content-Type": []string{"application/json"}}
	cookies := []*http.Cookie{{Name: "session_id", Value: "abc123"}}
	token := "abc123"
	securityScheme := auth.SecurityScheme(auth.NewAuthorizationBearerSecurityScheme("token", &token))
	securitySchemes := []auth.SecurityScheme{securityScheme}

	reporter := report.NewReporterWithCurl(method, url, data, header, cookies, securitySchemes)

	issue := report.Issue{
		ID:   "id",
		Name: "test",
	}
	sr := report.NewScanReport("id", "test", nil).AddIssueReport(report.NewIssueReport(issue).Fail())
	reporter.AddReport(sr)
	expectedIssue := &report.IssueReport{
		Issue:  issue,
		Status: report.IssueReportStatusFailed,
	}

	assert.NotEmpty(t, reporter.ScanReports)
	assert.Equal(t, 1, len(reporter.ScanReports))
	assert.Equal(t, sr, reporter.ScanReports[0])
	assert.NotEmpty(t, reporter.Curl.Issues)
	assert.Equal(t, 1, len(reporter.Curl.Issues))
	assert.Equal(t, expectedIssue, reporter.Curl.Issues[0])
}

func TestNewReporterWithOpenAPIDoc(t *testing.T) {
	openapi, _ := openapilib.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	securitySchemesMap, _ := openapi.SecuritySchemeMap(auth.NewEmptySecuritySchemeValues())
	operations, _ := openapi.Operations(nil, securitySchemesMap)

	reporter := report.NewReporterWithOpenAPIDoc(openapi.Doc, operations)

	assert.NotNil(t, reporter)
	assert.NotNil(t, reporter.OpenAPI)
	assert.Empty(t, reporter.ScanReports)
}

func TestReporterWithOpenAPIDoc_AddReport(t *testing.T) {
	openapi, _ := openapilib.LoadOpenAPI(context.Background(), "../test/stub/simple_http_bearer.openapi.json")
	securitySchemesMap, _ := openapi.SecuritySchemeMap(auth.NewEmptySecuritySchemeValues())
	operations, _ := openapi.Operations(nil, securitySchemesMap)
	reporter := report.NewReporterWithOpenAPIDoc(openapi.Doc, operations)

	issue := report.Issue{
		ID:   "id",
		Name: "test",
	}
	sr := report.NewScanReport("id", "test", operations[0]).AddIssueReport(report.NewIssueReport(issue).Fail())
	reporter.AddReport(sr)
	expectedIssue := &report.IssueReport{
		Issue:  issue,
		Status: report.IssueReportStatusFailed,
	}

	assert.NotEmpty(t, reporter.ScanReports)
	assert.Equal(t, 1, len(reporter.ScanReports))
	assert.Equal(t, sr, reporter.ScanReports[0])
	assert.NotEmpty(t, reporter.OpenAPI.Paths["/"][http.MethodGet].Issues)
	assert.Equal(t, 1, len(reporter.OpenAPI.Paths["/"][http.MethodGet].Issues))
	assert.Equal(t, expectedIssue, reporter.OpenAPI.Paths["/"][http.MethodGet].Issues[0])
}

func TestReporter_NoHasHighRiskOrHigherSeverityVulnerability_WhenNoReport(t *testing.T) {
	reporter := report.NewReporter()
	assert.False(t, reporter.HasHighRiskOrHigherSeverityIssue())
}

func TestReporter_NoHasVulnerability_WhenNoFailedReport(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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

func TestReporter_GetIssueReports_NoReports(t *testing.T) {
	reporter := report.NewReporter()
	reports := reporter.GetIssueReports()
	assert.Empty(t, reports)
}

func TestReporter_GetIssueReports_SingleReport(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	reporter.AddReport(sr)

	reports := reporter.GetIssueReports()
	assert.NotEmpty(t, reports)
	assert.Equal(t, 1, len(reports))
	assert.Equal(t, "test", reports[0].Issue.Name)
}

func TestReporter_GetIssueReports_MultipleReports(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
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

	reports := reporter.GetIssueReports()
	assert.NotEmpty(t, reports)
	assert.Equal(t, 2, len(reports))
	assert.Equal(t, "test1", reports[0].Issue.Name)
	assert.Equal(t, "test2", reports[1].Issue.Name)
}

func TestReporter_GetScanReportByID_NoReports(t *testing.T) {
	reporter := report.NewReporter()
	report := reporter.GetScanReportByID("nonexistent_id")
	assert.Nil(t, report)
}

func TestReporter_GetScanReportByID_SingleReport(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	reporter.AddReport(sr)

	report := reporter.GetScanReportByID("id")
	assert.NotNil(t, report)
	assert.Equal(t, "id", report.ID)
}

func TestReporter_GetScanReportByID_MultipleReports(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr1 := report.NewScanReport("id1", "test1", operation)
	sr2 := report.NewScanReport("id2", "test2", operation)
	reporter.AddReport(sr1)
	reporter.AddReport(sr2)

	report1 := reporter.GetScanReportByID("id1")
	report2 := reporter.GetScanReportByID("id2")

	assert.NotNil(t, report1)
	assert.Equal(t, "id1", report1.ID)
	assert.NotNil(t, report2)
	assert.Equal(t, "id2", report2.ID)
}

func TestReporter_GetScanReportByID_NonexistentID(t *testing.T) {
	reporter := report.NewReporter()
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	reporter.AddReport(sr)

	report := reporter.GetScanReportByID("nonexistent_id")
	assert.Nil(t, report)
}
