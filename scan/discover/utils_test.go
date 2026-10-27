package discover_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan/discover"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})
	httpmock.RegisterResponder(http.MethodGet, seclistUrl, httpmock.NewBytesResponder(http.StatusNotFound, nil))
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	_, err := discover.DownloadAndScanURLs(context.Background(), "test", seclistUrl, op, securityScheme)

	assert.Error(t, err)
	assert.EqualError(t, err, "sec list download failed")
}

func TestDownloadAndScanURLs_Passed_WhenNotFoundURLs(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	seclistUrl := "http://localhost:1234/passed_seclist"
	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})

	httpmock.RegisterResponder(
		http.MethodGet,
		seclistUrl,
		httpmock.NewBytesResponder(http.StatusOK, []byte("path1\npath2")),
	)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path1", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path2", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))

	f, err := discover.DownloadAndScanURLs(context.Background(), "test", seclistUrl, op, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 3, httpmock.GetTotalCallCount())
	assert.Nil(t, f)
}

func TestDownloadAndScanURLs_Failed_WhenFoundExposedURLs(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	seclistUrl := "http://localhost:1234/failed_seclist"
	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})

	httpmock.RegisterResponder(
		http.MethodGet,
		seclistUrl,
		httpmock.NewBytesResponder(http.StatusOK, []byte("path1\npath2")),
	)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path1", httpmock.NewStringResponder(http.StatusNotFound, "Not Found"))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/path2", httpmock.NewStringResponder(http.StatusOK, "OK"))

	f, err := discover.DownloadAndScanURLs(context.Background(), "test", seclistUrl, op, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 3, httpmock.GetTotalCallCount())
	require.NotNil(t, f)
	assert.Equal(t, "http://localhost:1234/path2", f.Parameter)
}

func TestScanURLs_DoesNotHangWhenSomeRequestsFail(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/exposed", httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterResponder(http.MethodGet, "http://localhost:1234/also-exposed", httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(httpmock.NewErrorResponder(errors.New("connection reset")))

	// the first request of the chunk fails, which used to drop the rest of
	// the chunk and hang the collector
	scanUrls := []string{"/failing", "/exposed", "/missing", "/also-exposed"}
	f, err := discover.ScanURLs(context.Background(), scanUrls, op, securityScheme)

	require.NoError(t, err)
	require.NotNil(t, f)
	assert.Equal(t, "http://localhost:1234/exposed", f.Parameter)
	assert.Equal(t, "http://localhost:1234/exposed, http://localhost:1234/also-exposed", f.Extra["discovered_urls"])
}

func TestScanURLs_ReturnsErrorWhenEveryRequestFails(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{})
	httpmock.ActivateNonDefault(client.Client)
	t.Cleanup(httpmock.DeactivateAndReset)

	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:1234", nil, client)
	httpmock.RegisterNoResponder(httpmock.NewErrorResponder(errors.New("connection refused")))

	f, err := discover.ScanURLs(context.Background(), []string{"/a", "/b"}, op, securityScheme)

	assert.Nil(t, f)
	assert.ErrorContains(t, err, "connection refused")
}
