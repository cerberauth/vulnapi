package report_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewOperationSecurityScheme(t *testing.T) {
	inHeader := auth.InHeader
	value := "test"
	noneTokenFormat := auth.NoneTokenFormat

	tests := []struct {
		name           string
		securityScheme *auth.SecurityScheme
		want           report.OperationSecurityScheme
	}{
		{
			name:           "No Auth",
			securityScheme: auth.MustNewNoAuthSecurityScheme(),
			want: report.OperationSecurityScheme{
				Type:   auth.None,
				Scheme: auth.NoneScheme,
				In:     nil,
				Name:   "no_auth",
			},
		},
		{
			name:           "Bearer Token",
			securityScheme: auth.MustNewAuthorizationBearerSecurityScheme("test", &value),
			want: report.OperationSecurityScheme{
				Type:        auth.HttpType,
				Scheme:      auth.BearerScheme,
				In:          &inHeader,
				TokenFormat: &noneTokenFormat,
				Name:        "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := report.NewOperationSecurityScheme(tt.securityScheme)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewScanReport(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.NotNil(t, sr)
	assert.Equal(t, "id", sr.ID)
	assert.Equal(t, "test", sr.Name)
	assert.NotZero(t, sr.StartTime)
}

func TestScanReport_Start(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	startTime := sr.StartTime
	time.Sleep(1 * time.Second)
	sr.Start()
	assert.NotEqual(t, startTime, sr.StartTime)
}

func TestScanReport_End(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	endTime := sr.EndTime
	time.Sleep(1 * time.Second)
	sr.End()
	assert.NotEqual(t, endTime, sr.EndTime)
}

func TestScanReport_WithData(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	data := map[string]string{
		"test": "test",
	}
	sr.WithData(data)
	assert.Equal(t, data, sr.Data)
}

func TestScanReport_GetData(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	data := map[string]string{
		"test": "test",
	}
	sr.WithData(data)
	assert.Equal(t, data, sr.GetData())
}

func TestScanReport_HasData(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasData())

	data := map[string]string{
		"test": "test",
	}
	sr.WithData(data)
	assert.True(t, sr.HasData())
}

func TestScanReport_AddScanAttempt(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	expectedScanAttempt := report.ScanReportScan{}

	sr.AddScanAttempt(&scan.IssueScanAttempt{})

	assert.Equal(t, 1, len(sr.GetScanAttempts()))
	assert.Equal(t, expectedScanAttempt, sr.GetScanAttempts()[0])
}

func TestScanReport_AddIssueReport(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	IssueReport := &report.IssueReport{}
	sr.AddIssueReport(IssueReport)
	assert.Equal(t, 1, len(sr.GetIssueReports()))
	assert.Equal(t, IssueReport, sr.GetIssueReports()[0])
}

func TestScanReport_HasFailedIssueReport(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasFailedIssueReport())

	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	assert.True(t, sr.HasFailedIssueReport())
}

func TestScanReport_HasOnlyFailedIssueReport(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasFailedIssueReport())

	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Fail()
	sr.AddIssueReport(IssueReport)
	assert.True(t, sr.HasFailedIssueReport())
}

func TestScanReport_HasOnlyPassedIssueReport(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasFailedIssueReport())

	issue := report.Issue{
		Name: "test",
	}
	IssueReport := report.NewIssueReport(issue).Pass()
	sr.AddIssueReport(IssueReport)
	assert.False(t, sr.HasFailedIssueReport())
}

func TestScanReport_GetErrors(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.Empty(t, sr.GetErrors())

	sr.AddScanAttempt(&scan.IssueScanAttempt{
		Err: errors.New("test"),
	})
	assert.NotEmpty(t, sr.GetErrors())
	assert.Equal(t, 1, len(sr.GetErrors()))
}

func TestMarshalJSON(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	scanAttempt := &scan.IssueScanAttempt{
		Err: nil,
	}
	sr.AddScanAttempt(scanAttempt)
	IssueReport := &report.IssueReport{}
	sr.AddIssueReport(IssueReport)

	_, err := json.Marshal(sr)

	assert.NoError(t, err)
}

func TestScanReport_GetIssueReports(t *testing.T) {
	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.Empty(t, sr.GetIssueReports())

	issueReport1 := &report.IssueReport{}
	issueReport2 := &report.IssueReport{}
	sr.AddIssueReport(issueReport1)
	sr.AddIssueReport(issueReport2)

	issueReports := sr.GetIssueReports()
	assert.Equal(t, 2, len(issueReports))
	assert.Equal(t, issueReport1, issueReports[0])
	assert.Equal(t, issueReport2, issueReports[1])
}
