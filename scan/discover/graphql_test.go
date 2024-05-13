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
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	report, err := discover.GraphqlIntrospectionScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 1)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestGetGraphqlIntrospectionScanHandler(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	report, err := discover.GraphqlIntrospectionScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 1)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestGraphqlIntrospectionScanHandlerWithKnownGraphQLIntrospectionEndpoint(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/graphql", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.GraphqlIntrospectionEnabledSeverityLevel,

		ID:   discover.GraphqlIntrospectionEnabledVulnerabilityID,
		Name: discover.GraphqlIntrospectionEnabledVulnerabilityName,
		URL:  discover.GraphqlIntrospectionEnabledVulnerabilityURL,
	}

	report, err := discover.GraphqlIntrospectionScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	// assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Request.URL.String(), expectedReport.Operation.Request.URL.String())
}

func TestGetGraphqlIntrospectionScanHandlerWithKnownGraphQLIntrospectionEndpoint(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/graphql", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.GraphqlIntrospectionEnabledSeverityLevel,

		ID:   discover.GraphqlIntrospectionEnabledVulnerabilityID,
		Name: discover.GraphqlIntrospectionEnabledVulnerabilityName,
		URL:  discover.GraphqlIntrospectionEnabledVulnerabilityURL,
	}

	report, err := discover.GraphqlIntrospectionScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	// assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Request.URL.String(), expectedReport.Operation.Request.URL.String())
}

func TestDiscoverableScannerWithNoDiscoverableGraphqlPath(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	report, err := discover.DiscoverableGraphQLPathScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 7)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestDiscoverableScannerWithOneDiscoverableGraphQLPath(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/graphql", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(func(req *http.Request) (*http.Response, error) {
		return httpmock.NewStringResponse(http.StatusNotFound, "Not Found"), nil
	})

	expectedReport := report.VulnerabilityReport{
		SeverityLevel: discover.DiscoverableGraphQLPathSeverityLevel,

		ID:   discover.DiscoverableGraphQLPathVulnerabilityID,
		Name: discover.DiscoverableGraphQLPathVulnerabilityName,
		URL:  discover.DiscoverableGraphQLPathVulnerabilityURL,
	}

	report, err := discover.DiscoverableGraphQLPathScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0].Name, expectedReport.Name)
	// assert.Equal(t, report.GetVulnerabilityReports()[0].Operation.Request.URL.String(), expectedReport.Operation.Request.URL.String())
}
