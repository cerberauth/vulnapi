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

func TestGraphqlIntrospectionScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080", http.MethodPost, nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(404, "Not Found"), nil
	})

	report, err := discover.GraphqlIntrospectionScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 1)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestGraphqlIntrospectionScanHandlerWithKnownGraphQLIntrospectionEndpoint(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/graphql", http.MethodPost, nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(404, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.GraphqlIntrospectionEnabledSeverityLevel,
		Name:          discover.GraphqlIntrospectionEnabledVulnerabilityName,
		Description:   discover.GraphqlIntrospectionEnabledVulnerabilityDescription,
		Operation:     operation,
	}

	report, err := discover.GraphqlIntrospectionScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Request.URL.String(), expectedReport.Operation.Request.URL.String())
}

func TestDiscoverableScannerWithNoDiscoverableGraphqlPath(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(404, "Not Found"), nil
	})

	report, err := discover.DiscoverableGraphQLPathScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 7)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestDiscoverableScannerWithOneDiscoverableGraphQLPath(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/graphql", "GET", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(404, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.DiscoverableGraphQLPathSeverityLevel,
		Name:          discover.DiscoverableGraphQLPathVulnerabilityName,
		Description:   discover.DiscoverableGraphQLPathVulnerabilityDescription,
		Operation:     operation,
	}

	report, err := discover.DiscoverableGraphQLPathScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Request.URL.String(), expectedReport.Operation.Request.URL.String())
}
