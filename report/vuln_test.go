package report_test

import (
	"testing"

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
		Url:           "https://example.com/vulnerability",
	}
	expected := "[high][Test Vulnerability] https://example.com/vulnerability: This is a test vulnerability"
	assert.Equal(t, expected, vr.String())
}
