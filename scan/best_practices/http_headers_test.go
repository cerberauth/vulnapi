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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}

	header := getValidHTTPHeaders(&o)
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestHTTPHeadersBestPracticesWithoutCSPScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CSPHTTPHeaderSeverityLevel,
		Name:          bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.CSPHTTPHeaderIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Del(bestpractices.CSPHTTPHeader)
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CSPHTTPHeaderSeverityLevel,
		Name:          bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		Description:   bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Set(bestpractices.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'")
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CSPHTTPHeaderSeverityLevel,
		Name:          bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityName,
		Description:   bestpractices.CSPHTTPHeaderFrameAncestorsIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Set(bestpractices.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'; frame-ancestors 'http://example.com'")
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CORSHTTPHeaderSeverityLevel,
		Name:          bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.CORSHTTPHeaderIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Del(bestpractices.CORSOriginHTTPHeader)
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.CORSHTTPHeaderSeverityLevel,
		Name:          bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityName,
		Description:   bestpractices.CORSHTTPHeaderIsPermisiveVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Set(bestpractices.CORSOriginHTTPHeader, "*")
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.HSTSHTTPHeaderSeverityLevel,
		Name:          bestpractices.HSTSHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.HSTSHTTPHeaderIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Del(bestpractices.HSTSHTTPHeader)
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetSeverityLevel,
		Name:          bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.XContentTypeOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Del(bestpractices.XContentTypeOptionsHTTPHeader)
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

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
	o := request.Operation{
		Method: "GET",
		Url:    "http://localhost:8080/",
	}
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: bestpractices.XFrameOptionsHTTPHeaderIsNotSetSeverityLevel,
		Name:          bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityName,
		Description:   bestpractices.XFrameOptionsHTTPHeaderIsNotSetVulnerabilityDescription,
		Url:           o.Url,
	}

	header := getValidHTTPHeaders(&o)
	header.Del(bestpractices.XFrameOptionsHTTPHeader)
	httpmock.RegisterResponder(o.Method, o.Url, httpmock.NewBytesResponder(204, nil).HeaderAdd(*header))

	report, err := bestpractices.HTTPHeadersBestPracticesScanHandler(&o, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}
