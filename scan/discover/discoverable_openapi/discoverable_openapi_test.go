package discoverableopenapi_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverableScanner_Passed_WhenNoDiscoverableGraphqlPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	report, err := discoverableopenapi.ScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 10)
	assert.True(t, report.Issues[0].HasPassed())
}

func TestDiscoverableScanner_Failed_WhenOneOpenAPIFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/swagger/v1/swagger.json", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	report, err := discoverableopenapi.ScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.Issues[0].HasFailed())
}
