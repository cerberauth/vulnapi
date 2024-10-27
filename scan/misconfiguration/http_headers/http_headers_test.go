package httpheaders_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	httpheaders "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getValidHTTPHeaders(_ *request.Operation) http.Header {
	header := http.Header{}
	header.Add(httpheaders.CSPHTTPHeader, "frame-ancestors 'none'")
	header.Add(httpheaders.CORSOriginHTTPHeader, "http://localhost:8080")
	header.Add(httpheaders.HSTSHTTPHeader, "max-age=63072000; includeSubDomains; preload")
	header.Add(httpheaders.XContentTypeOptionsHTTPHeader, "nosniff")
	header.Add(httpheaders.XFrameOptionsHTTPHeader, "DENY")

	return header
}

func TestHTTPHeadersScanHandler_Passed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(getValidHTTPHeaders(operation)))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 7, len(report.Issues))
	assert.False(t, report.HasFailedIssueReport())
	assert.True(t, report.Issues[0].HasPassed())
	assert.True(t, report.Issues[2].HasPassed())
	assert.True(t, report.Issues[3].HasPassed())
	assert.True(t, report.Issues[4].HasPassed())
	assert.True(t, report.Issues[5].HasPassed())
	assert.True(t, report.Issues[6].HasPassed())
}

func TestHTTPHeadersBestPracticesWithoutCSPScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Del(httpheaders.CSPHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithoutFrameAncestorsCSPDirectiveScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Set(httpheaders.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'")
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithNotNoneFrameAncestorsCSPDirectiveScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Set(httpheaders.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'; frame-ancestors 'http://example.com'")
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithoutCORSScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Del(httpheaders.CORSOriginHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithPermissiveCORSScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Set(httpheaders.CORSOriginHTTPHeader, "*")
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithoutHSTSScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Del(httpheaders.HSTSHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithoutXContentTypeOptionsScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Del(httpheaders.XContentTypeOptionsHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}

func TestHTTPHeadersBestPracticesWithoutXFrameOptionsScanHandler(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	header := getValidHTTPHeaders(operation)
	header.Del(httpheaders.XFrameOptionsHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	report, err := httpheaders.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedIssueReport())
}
