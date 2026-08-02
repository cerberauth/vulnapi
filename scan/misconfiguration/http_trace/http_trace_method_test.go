package httptrace_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httptrace "github.com/cerberauth/vulnapi/scan/misconfiguration/http_trace"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runHTTPTraceCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httptrace.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
}

func TestHTTPTraceMethodScanHandler_Passed_WhenNotOKResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(http.MethodTrace, op.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	result, err := runHTTPTraceCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestHTTPTraceMethodScanHandler_Failed_WhenTraceIsEnabled(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(http.MethodTrace, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	result, err := runHTTPTraceCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}
