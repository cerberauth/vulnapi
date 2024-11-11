package introspectionenabled_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	introspectionenabled "github.com/cerberauth/vulnapi/scan/graphql/introspection_enabled"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGraphqlIntrospectionScanHandler_Failed_WhenRespondHTTPStatusIsOK(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	resBody := []byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`)
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, resBody))
	httpmock.RegisterResponder(http.MethodGet, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, resBody))

	report, err := introspectionenabled.ScanHandler(operation, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
}

func TestGraphqlIntrospectionScanHandler_Failed_WhenRespond_GETMethodOnly_HTTPStatusIsOK(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	resBody := []byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`)
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), httpmock.NewBytesResponder(http.StatusBadRequest, nil))
	httpmock.RegisterResponder(http.MethodGet, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, resBody))

	report, err := introspectionenabled.ScanHandler(operation, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
}

func TestGraphqlIntrospectionScanHandler_Passed_WhenBadRequestStatus(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), httpmock.NewBytesResponder(http.StatusBadRequest, nil))
	httpmock.RegisterResponder(http.MethodGet, operation.URL.String(), httpmock.NewBytesResponder(http.StatusBadRequest, nil))

	report, err := introspectionenabled.ScanHandler(operation, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasPassed())
}

func TestGraphqlIntrospectionScanHandler_Passed_WhenOKStatusButNoQuery(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(http.MethodPost, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterResponder(http.MethodGet, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := introspectionenabled.ScanHandler(operation, auth.MustNewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasPassed())
}
