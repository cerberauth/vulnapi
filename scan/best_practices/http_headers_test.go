package bestpractices_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getValidHTTPHeaders(o *request.Operation) *http.Header {
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
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	header := getValidHTTPHeaders(operation)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

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
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CSPHTTPHeaderIsNotSetSeverityLevel,

		ID:   bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityID,
		Name: bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityName,
		URL:  bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.CSPHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithoutFrameAncestorsCSPDirectiveScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetSeverityLevel,

		ID:   bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityID,
		Name: bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		URL:  bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Set(bestpractices.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithNotNoneFrameAncestorsCSPDirectiveScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetSeverityLevel,

		ID:   bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityID,
		Name: bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		URL:  bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Set(bestpractices.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'; frame-ancestors 'http://example.com'")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithoutCORSScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CORSHTTPHeaderIsNotSetSeverityLevel,

		ID:   bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityID,
		Name: bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityName,
		URL:  bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.CORSOriginHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithPermissiveCORSScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CORSHTTPHeaderIsPermisiveSeverityLevel,

		ID:   bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityID,
		Name: bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityName,
		URL:  bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Set(bestpractices.CORSOriginHTTPHeader, "*")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithoutHSTSScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.HTSTHTTPHeaderIsNotSetSeverityLevel,

		ID:   bestpractices.HTSTHTTPHeaderIsNotSetVulnerabilityID,
		Name: bestpractices.HSTSHTTPHeaderIsNotSetVulnerabilityName,
		URL:  bestpractices.HSTSHTTPHeaderIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.HSTSHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithoutXContentTypeOptionsScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel,

		ID:   bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityID,
		Name: bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
		URL:  bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.XContentTypeOptionsHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestHTTPHeadersBestPracticesWithoutXFrameOptionsScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.XFrameOptionsHTTPHeaderIsNotSetSeverityLevel,

		ID:   bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityID,
		Name: bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
		URL:  bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityURL,

		Operation: operation,
	}

	header := getValidHTTPHeaders(operation)
	header.Del(bestpractices.XFrameOptionsHTTPHeader)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}
