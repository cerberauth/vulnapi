package bestpractices_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTraceMethodScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder("TRACE", operation.Url, httpmock.NewBytesResponder(405, nil))

	report, err := bestpractices.HTTPTraceMethodScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPTraceMethodWhenTraceIsEnabledScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.HTTPTraceMethodSeverityLevel,
		Name:          bestpractices.HTTPTraceMethodVulnerabilityName,
		Description:   bestpractices.HTTPTraceMethodVulnerabilityDescription,
		Operation:     operation,
	}

	httpmock.RegisterResponder("TRACE", operation.Url, httpmock.NewBytesResponder(204, nil))

	report, err := bestpractices.HTTPTraceMethodScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}
