package report_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanReport(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.NotNil(t, sr)
	assert.Equal(t, "id", sr.ID)
	assert.Equal(t, "test", sr.Name)
	assert.Equal(t, operation, sr.Operation)
	assert.NotZero(t, sr.StartTime)
}

func TestScanReport_Start(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	startTime := sr.StartTime
	time.Sleep(1 * time.Second)
	sr.Start()
	assert.NotEqual(t, startTime, sr.StartTime)
}

func TestScanReport_End(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	endTime := sr.EndTime
	time.Sleep(1 * time.Second)
	sr.End()
	assert.NotEqual(t, endTime, sr.EndTime)
}

func TestScanReport_AddScanAttempt(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	scanAttempt := &report.VulnerabilityScanAttempt{
		Request:  &http.Request{},
		Response: &http.Response{},
		Err:      nil,
	}
	sr.AddScanAttempt(scanAttempt)
	assert.Equal(t, 1, len(sr.GetScanAttempts()))
	assert.Equal(t, scanAttempt, sr.GetScanAttempts()[0])
}

func TestScanReport_AddVulnerabilityReport(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.Equal(t, 1, len(sr.GetVulnerabilityReports()))
	assert.Equal(t, vulnerabilityReport, sr.GetVulnerabilityReports()[0])
}

func TestScanReport_HasVulnerabilityReport(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	assert.False(t, sr.HasVulnerabilityReport())

	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.True(t, sr.HasVulnerabilityReport())
}

func TestMarshalJSON(t *testing.T) {
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodPost, "http://localhost:8080/", nil, nil, nil)
	sr := report.NewScanReport("id", "test", operation)
	scanAttempt := &report.VulnerabilityScanAttempt{
		Request:  &http.Request{},
		Response: &http.Response{},
		Err:      nil,
	}
	sr.AddScanAttempt(scanAttempt)
	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)

	_, err := json.Marshal(sr)

	assert.NoError(t, err)
}
