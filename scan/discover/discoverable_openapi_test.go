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
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	report, err := discover.DiscoverableOpenAPIScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 10)
	assert.False(t, report.HasFailedVulnerabilityReport())
}

func TestDiscoverableScannerWithOneDiscoverableOpenAPI(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/swagger/v1/swagger.json", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.DiscoverableOpenAPISeverityLevel,

		ID:   discover.DiscoverableOpenAPIVulnerabilityID,
		Name: discover.DiscoverableOpenAPIVulnerabilityName,
		URL:  discover.DiscoverableOpenAPIVulnerabilityURL,
	}

	report, err := discover.DiscoverableOpenAPIScanHandler(operation, auth.NewNoAuthSecurityScheme())

	HasFailedVulnerabilityReport := report.HasFailedVulnerabilityReport()
	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, HasFailedVulnerabilityReport)
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	// assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Request.URL.String(), expectedReport.Operation.Request.URL.String())
}
