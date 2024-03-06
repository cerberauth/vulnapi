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
		SeverityLevel: bestpractices.CSPHTTPHeaderSeverityLevel,
		Name:          bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
		SeverityLevel: bestpractices.CSPHTTPHeaderSeverityLevel,
		Name:          bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		Description:   bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
		SeverityLevel: bestpractices.CSPHTTPHeaderSeverityLevel,
		Name:          bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		Description:   bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
		SeverityLevel: bestpractices.CORSHTTPHeaderSeverityLevel,
		Name:          bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
		SeverityLevel: bestpractices.CORSHTTPHeaderSeverityLevel,
		Name:          bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityName,
		Description:   bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityDescription,
		Operation:     operation,
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
		SeverityLevel: bestpractices.HSTSHTTPHeaderSeverityLevel,
		Name:          bestpractices.HSTSHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.HSTSHTTPHeaderIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
		Name:          bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
		Name:          bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
		Operation:     operation,
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
