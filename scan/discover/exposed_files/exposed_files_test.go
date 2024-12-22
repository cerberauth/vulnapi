package exposedfiles_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	exposedfiles "github.com/cerberauth/vulnapi/scan/discover/exposed_files"
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

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	report, err := exposedfiles.ScanHandler(op, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 7)
	assert.True(t, report.Issues[0].HasPassed())
}

func TestDiscoverableScanner_Failed_WhenOneGraphQLPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/.aws/credentials", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	report, err := exposedfiles.ScanHandler(operation, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.Issues[0].HasFailed())
}
