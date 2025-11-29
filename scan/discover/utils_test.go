package discover_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
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
			inputURL: "http://localhost:1234",
			expected: "http://localhost:1234",
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

func TestDownloadAndScanURLs_Failed_WhenNotFoundSeclist(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	seclistUrl := "http://localhost:1234/not_found_seclist"
	securitySchemes := []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	r := report.NewScanReport("test", "test", operation)
	vulnReport := report.NewIssueReport(report.Issue{})
	httpmock.RegisterResponder(http.MethodGet, seclistUrl, httpmock.NewBytesResponder(http.StatusNotFound, nil))
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	_, err := discover.DownloadAndScanURLs("test", seclistUrl, r, vulnReport, operation, securitySchemes[0])

	assert.Error(t, err)
	assert.EqualError(t, err, "sec list download failed")
}

func TestDownloadAndScanURLs_Passed_WhenNotFoundURLs(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	seclistUrl := "http://localhost:1234/passed_seclist"
	securitySchemes := []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	r := report.NewScanReport("test", "test", operation)
	vulnReport := report.NewIssueReport(report.Issue{})

	httpmock.RegisterResponder(
		http.MethodGet,
		seclistUrl,
		httpmock.NewBytesResponder(http.StatusOK, []byte("path1\npath2")),
	)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path1", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path2", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))

	_, err := discover.DownloadAndScanURLs("test", seclistUrl, r, vulnReport, operation, securitySchemes[0])

	assert.NoError(t, err)
	assert.Equal(t, 3, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(r.Scans))
	assert.Equal(t, 2, len(vulnReport.Scans))
	assert.True(t, vulnReport.Scans[0].HasPassed())
	assert.True(t, vulnReport.Scans[1].HasPassed())
	assert.True(t, vulnReport.HasPassed())
}

func TestDownloadAndScanURLs_Failed_WhenFoundExposedURLs(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	seclistUrl := "http://localhost:1234/failed_seclist"
	securitySchemes := []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	operation.SetSecuritySchemes(securitySchemes)
	r := report.NewScanReport("test", "test", operation)
	vulnReport := report.NewIssueReport(report.Issue{})

	httpmock.RegisterResponder(
		http.MethodGet,
		seclistUrl,
		httpmock.NewBytesResponder(http.StatusOK, []byte("path1\npath2")),
	)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path1", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path2", httpmock.NewStringResponder(http.StatusOK, "OK"))

	_, err := discover.DownloadAndScanURLs("test", seclistUrl, r, vulnReport, operation, securitySchemes[0])

	assert.NoError(t, err)
	assert.Equal(t, 3, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(r.Scans))
	assert.True(t, vulnReport.Scans[0].HasPassed())
	assert.True(t, vulnReport.Scans[1].HasFailed())
	assert.True(t, vulnReport.HasFailed())
}
