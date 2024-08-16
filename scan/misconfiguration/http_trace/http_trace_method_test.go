package httptrace_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	httptrace "github.com/cerberauth/vulnapi/scan/misconfiguration/http_trace"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTraceMethodScanHandler_Passed_WhenNotOKResponse(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(http.MethodTrace, operation.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := httptrace.ScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Vulns[0].HasPassed())
}

func TestHTTPTraceMethodScanHandler_Failed_WhenTraceIsEnabled(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(http.MethodTrace, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := httptrace.ScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Vulns[0].HasFailed())
}
