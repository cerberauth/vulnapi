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

func getValidHTTPHeaders(_ *request.Operation) *http.Header {
	header := http.Header{}
	header.Add(bestpractices.CSPHTTPHeader, "frame-ancestors 'none'")
	header.Add(bestpractices.CORSOriginHTTPHeader, "http://localhost:8080")
	header.Add(bestpractices.HSTSHTTPHeader, "max-age=63072000; includeSubDomains; preload")
	header.Add(bestpractices.XContentTypeOptionsHTTPHeader, "nosniff")
	header.Add(bestpractices.XFrameOptionsHTTPHeader, "DENY")

	return &header
}

func TestHTTPHeadersBestPracticesScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutCSPScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.CSPHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutFrameAncestorsCSPDirectiveScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Set(bestpractices.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithNotNoneFrameAncestorsCSPDirectiveScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Set(bestpractices.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'; frame-ancestors 'http://example.com'")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutCORSScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.CORSOriginHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithPermissiveCORSScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Set(bestpractices.CORSOriginHTTPHeader, "*")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutHSTSScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.HSTSHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutXContentTypeOptionsScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.XContentTypeOptionsHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutXFrameOptionsScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.XFrameOptionsHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}
