package report_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanReport(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.NotNil(t, sr)
	assert.Equal(t, "id", sr.ID)
	assert.Equal(t, "test", sr.Name)
	assert.NotZero(t, sr.StartTime)
}

func TestScanReport_Start(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	startTime := sr.StartTime
	time.Sleep(1 * time.Second)
	sr.Start()
	assert.NotEqual(t, startTime, sr.StartTime)
}

func TestScanReport_End(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	endTime := sr.EndTime
	time.Sleep(1 * time.Second)
	sr.End()
	assert.NotEqual(t, endTime, sr.EndTime)
}

func TestScanReport_WithData(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	data := map[string]string{
		"test": "test",
	}
	sr.WithData(data)
	assert.Equal(t, data, sr.Data)
}

func TestScanReport_GetData(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	data := map[string]string{
		"test": "test",
	}
	sr.WithData(data)
	assert.Equal(t, data, sr.GetData())
}

func TestScanReport_HasData(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasData())

	data := map[string]string{
		"test": "test",
	}
	sr.WithData(data)
	assert.True(t, sr.HasData())
}

func TestScanReport_AddScanAttempt(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	expectedScanAttempt := report.ReportScan{}

	sr.AddScanAttempt(&scan.VulnerabilityScanAttempt{})

	assert.Equal(t, 1, len(sr.GetScanAttempts()))
	assert.Equal(t, expectedScanAttempt, sr.GetScanAttempts()[0])
}

func TestScanReport_AddVulnerabilityReport(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.Equal(t, 1, len(sr.GetVulnerabilityReports()))
	assert.Equal(t, vulnerabilityReport, sr.GetVulnerabilityReports()[0])
}

func TestScanReport_HasFailedVulnerabilityReport(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasFailedVulnerabilityReport())

	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.True(t, sr.HasFailedVulnerabilityReport())
}

func TestScanReport_HasOnlyFailedVulnerabilityReport(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasFailedVulnerabilityReport())

	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Fail()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.True(t, sr.HasFailedVulnerabilityReport())
}

func TestScanReport_HasOnlyPassedVulnerabilityReport(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasFailedVulnerabilityReport())

	issue := report.Issue{
		Name: "test",
	}
	vulnerabilityReport := report.NewVulnerabilityReport(issue).Pass()
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.False(t, sr.HasFailedVulnerabilityReport())
}

func TestScanReport_GetErrors(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.Empty(t, sr.GetErrors())

	sr.AddScanAttempt(&scan.VulnerabilityScanAttempt{
		Err: errors.New("test"),
	})
	assert.NotEmpty(t, sr.GetErrors())
	assert.Equal(t, 1, len(sr.GetErrors()))
}

func TestMarshalJSON(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	scanAttempt := &scan.VulnerabilityScanAttempt{
		Err: nil,
	}
	sr.AddScanAttempt(scanAttempt)
	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)

	_, err := json.Marshal(sr)

	assert.NoError(t, err)
}
