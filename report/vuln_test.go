package report_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestVulnerabilityReport_WithOperation(t *testing.T) {
	vr := &report.VulnerabilityReport{}
	operation, _ := request.NewOperation(http.MethodPost, "https://example.com/vulnerability", nil, nil, nil)

	vr.WithOperation(operation)

	assert.Equal(t, operation, vr.Operation)
}

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
	operation, _ := request.NewOperation(http.MethodGet, "https://example.com/vulnerability", nil, nil, nil)
	vr := &report.VulnerabilityReport{
		SeverityLevel: 7.5,
		ID:            "test-vulnerability",
		Name:          "Test Vulnerability",
		URL:           "https://example.com/docs/vulnerability",

		Operation: operation,
	}
	expected := "[High][Test Vulnerability] GET https://example.com/vulnerability"
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
