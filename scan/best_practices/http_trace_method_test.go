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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}

	httpmock.RegisterResponder("TRACE", o.Url, httpmock.NewBytesResponder(405, nil))

	report, err := bestpractices.HTTPTraceMethodScanHandler(&o, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPTraceMethodWhenTraceIsEnabledScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.HTTPTraceMethodSeverityLevel,
		Name:          bestpractices.HTTPTraceMethodVulnerabilityName,
		Description:   bestpractices.HTTPTraceMethodVulnerabilityDescription,
		Url:           o.Url,
	}

	httpmock.RegisterResponder("TRACE", o.Url, httpmock.NewBytesResponder(204, nil))

	report, err := bestpractices.HTTPTraceMethodScanHandler(&o, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}
