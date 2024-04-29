package report_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanReport(t *testing.T) {
	sr := report.NewScanReport("id", "test")
	assert.NotNil(t, sr)
	assert.Equal(t, "id", sr.ID)
	assert.Equal(t, "test", sr.Name)
	assert.NotZero(t, sr.StartTime)
}

func TestScanReport_Start(t *testing.T) {
	sr := report.NewScanReport("id", "test")
	startTime := sr.StartTime
	time.Sleep(1 * time.Second)
	sr.Start()
	assert.NotEqual(t, startTime, sr.StartTime)
}

func TestScanReport_End(t *testing.T) {
	sr := report.NewScanReport("id", "test")
	endTime := sr.EndTime
	time.Sleep(1 * time.Second)
	sr.End()
	assert.NotEqual(t, endTime, sr.EndTime)
}

func TestScanReport_AddScanAttempt(t *testing.T) {
	sr := report.NewScanReport("id", "test")
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
	sr := report.NewScanReport("id", "test")
	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.Equal(t, 1, len(sr.GetVulnerabilityReports()))
	assert.Equal(t, vulnerabilityReport, sr.GetVulnerabilityReports()[0])
}

func TestScanReport_HasVulnerabilityReport(t *testing.T) {
	sr := report.NewScanReport("id", "test")
	assert.False(t, sr.HasVulnerabilityReport())

	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.True(t, sr.HasVulnerabilityReport())
}
