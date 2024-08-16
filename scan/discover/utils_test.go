package discover_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestExtractBaseURL(t *testing.T) {
	testCases := []struct {
		inputURL  string
		expected  string
		expectErr bool
	}{
		{
			inputURL: "https://example.com/path/to/resource",
			expected: "https://example.com",
		},
		{
			inputURL: "http://localhost:8080",
			expected: "http://localhost:8080",
		},
	}

	for _, tc := range testCases {
		input, err := url.Parse(tc.inputURL)
		if err != nil {
			t.Fatalf("failed to parse input URL: %v", err)
		}

		baseURL := discover.ExtractBaseURL(input)

		assert.Equal(t, tc.expected, baseURL.String())
	}
}

func TestCreateURLScanHandler_WithTimeout(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	seclistUrl := "http://localhost:8080/seclist"
	defaultUrls := []string{"/path1", "/path2"}
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080", nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	r := report.NewScanReport("test", "test", operation)
	vulnReport := &report.VulnerabilityReport{}
	handler := discover.CreateURLScanHandler("test", seclistUrl, defaultUrls, r, vulnReport)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	_, err := handler(operation, securitySchemes[0])

	assert.Error(t, err)
	assert.EqualError(t, err, "request has an unexpected error")
}

func TestCreateURLScanHandler_Passed_WhenNotFoundURLs(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	seclistUrl := "http://localhost:8080/seclist"
	defaultUrls := []string{"/path1", "/path2"}
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080", nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	r := report.NewScanReport("test", "test", operation)
	vulnReport := &report.VulnerabilityReport{}
	handler := discover.CreateURLScanHandler("test", seclistUrl, defaultUrls, r, vulnReport)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:8080/path1", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:8080/path2", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))

	_, err := handler(operation, securitySchemes[0])

	assert.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, r.Vulns[0].HasPassed())
}

func TestCreateURLScanHandler_Failed_WhenFoundExposedURLs(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	seclistUrl := "http://localhost:8080/seclist"
	defaultUrls := []string{"/path1", "/path2"}
	securitySchemes := []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080", nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	r := report.NewScanReport("test", "test", operation)
	vulnReport := &report.VulnerabilityReport{}

	handler := discover.CreateURLScanHandler("test", seclistUrl, defaultUrls, r, vulnReport)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:8080/path1", httpmock.NewStringResponder(http.StatusOK, "OK"))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:8080/path2", httpmock.NewStringResponder(http.StatusOK, "OK"))

	_, err := handler(operation, securitySchemes[0])

	assert.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, r.Vulns[0].HasFailed())
}
