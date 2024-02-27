package report_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewScanReport(t *testing.T) {
	sr := report.NewScanReport()
	assert.NotNil(t, sr)
	assert.NotZero(t, sr.StartTime)
}

func TestScanReport_Start(t *testing.T) {
	sr := report.NewScanReport()
	startTime := sr.StartTime
	time.Sleep(1 * time.Second)
	sr.Start()
	assert.NotEqual(t, startTime, sr.StartTime)
}

func TestScanReport_End(t *testing.T) {
	sr := report.NewScanReport()
	endTime := sr.EndTime
	time.Sleep(1 * time.Second)
	sr.End()
	assert.NotEqual(t, endTime, sr.EndTime)
}

func TestScanReport_AddScanAttempt(t *testing.T) {
	sr := report.NewScanReport()
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
	sr := report.NewScanReport()
	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.Equal(t, 1, len(sr.GetVulnerabilityReports()))
	assert.Equal(t, vulnerabilityReport, sr.GetVulnerabilityReports()[0])
}

func TestScanReport_HasVulnerabilityReport(t *testing.T) {
	sr := report.NewScanReport()
	assert.False(t, sr.HasVulnerabilityReport())

	vulnerabilityReport := &report.VulnerabilityReport{}
	sr.AddVulnerabilityReport(vulnerabilityReport)
	assert.True(t, sr.HasVulnerabilityReport())
}
