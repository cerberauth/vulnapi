package report_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestVulnerabilityReport_IsLowRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{SeverityLevel: 3.5}
	assert.True(t, vr.IsLowRiskSeverity())
}

func TestVulnerabilityReport_IsMediumRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{SeverityLevel: 5.5}
	assert.True(t, vr.IsMediumRiskSeverity())
}

func TestVulnerabilityReport_IsHighRiskSeverity(t *testing.T) {
	vr := &report.VulnerabilityReport{SeverityLevel: 9.5}
	assert.True(t, vr.IsHighRiskSeverity())
}

func TestVulnerabilityReport_String(t *testing.T) {
	vr := &report.VulnerabilityReport{
		SeverityLevel: 7.5,
		Name:          "Test Vulnerability",
		Description:   "This is a test vulnerability",

		Operation: &request.Operation{
			Method: "GET",
			Url:    "https://example.com/vulnerability",
		},
	}
	expected := "[High][Test Vulnerability] GET https://example.com/vulnerability: This is a test vulnerability"
	assert.Equal(t, expected, vr.String())
}
func TestVulnerabilityReport_SeverityLevelString(t *testing.T) {
	vr := &report.VulnerabilityReport{}

	// Test case for severity level >= 9
	vr.SeverityLevel = 9.5
	assert.Equal(t, "Critical", vr.SeverityLevelString())

	// Test case for severity level < 9 and >= 7
	vr.SeverityLevel = 7.5
	assert.Equal(t, "High", vr.SeverityLevelString())

	// Test case for severity level < 7 and >= 4
	vr.SeverityLevel = 4.5
	assert.Equal(t, "Medium", vr.SeverityLevelString())

	// Test case for severity level < 4 and >= 0.1
	vr.SeverityLevel = 0.5
	assert.Equal(t, "Low", vr.SeverityLevelString())

	// Test case for severity level < 0.1
	vr.SeverityLevel = 0.05
	assert.Equal(t, "None", vr.SeverityLevelString())
}
