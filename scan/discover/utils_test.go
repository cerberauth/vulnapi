package discover_test

import (
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/scan/discover"
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
