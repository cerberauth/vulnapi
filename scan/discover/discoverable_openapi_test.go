package discover_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverableScannerWithNoDiscoverableOpenAPI(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(404, "Not Found"), nil
	})

	report, err := discover.DiscoverableOpenAPIScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 10)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestDiscoverableScannerWithOneDiscoverableOpenAPI(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/openapi.yaml", "GET", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(404, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.DiscoverableOpenAPISeverityLevel,
		Name:          discover.DiscoverableOpenAPIVulnerabilityName,
		Description:   discover.DiscoverableOpenAPIVulnerabilityDescription,
		Operation:     operation,
	}

	report, err := discover.DiscoverableOpenAPIScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Url, expectedReport.Operation.Url)
}
