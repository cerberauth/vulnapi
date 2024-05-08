package bestpractices_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPTraceMethodScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder("TRACE", operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := bestpractices.HTTPTraceMethodScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPTraceMethodWhenTraceIsEnabledScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder("TRACE", operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	report, err := bestpractices.HTTPTraceMethodScanHandler(operation, auth.NewNoAuthSecurityScheme())

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}
