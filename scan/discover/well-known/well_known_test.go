package wellknown_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	wellknown "github.com/cerberauth/vulnapi/scan/discover/well-known"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoverableScanner_Passed_WhenNoDiscoverableWellKnownPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	report, err := wellknown.ScanHandler(op, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 5)
	assert.True(t, report.Issues[0].HasPassed())
}

func TestDiscoverableScanner_Failed_WhenOneWellKnownPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/.well-known/jwks.json", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	report, err := wellknown.ScanHandler(operation, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	assert.True(t, report.Issues[0].HasFailed())
}
