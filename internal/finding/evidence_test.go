package finding_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPEvidenceWithNilAttempt(t *testing.T) {
	assert.Nil(t, finding.NewHTTPEvidence(nil))
	assert.Nil(t, finding.NewHTTPEvidence(&finding.Attempt{}))
}

func TestNewHTTPEvidenceRedactsCredentialHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8080/", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Cookie", "session=secret-session")
	req.Header.Set("X-Custom-Token", "secret-api-key")
	req.Header.Set("Accept", "application/json")
	responseHeader := http.Header{}
	responseHeader.Set("Set-Cookie", "session=secret-session")
	responseHeader.Set("Content-Type", "application/json")
	attempt := &finding.Attempt{
		Request:  req,
		Response: &finding.Response{StatusCode: http.StatusOK, Header: responseHeader},
	}

	ev := finding.NewHTTPEvidence(attempt, "X-Custom-Token")

	require.NotNil(t, ev)
	assert.Equal(t, []string{enrich.RedactedValue}, ev.RequestHeaders["Authorization"])
	assert.Equal(t, []string{enrich.RedactedValue}, ev.RequestHeaders["Cookie"])
	assert.Equal(t, []string{enrich.RedactedValue}, ev.RequestHeaders["X-Custom-Token"])
	assert.Equal(t, []string{"application/json"}, ev.RequestHeaders["Accept"])
	assert.Equal(t, []string{enrich.RedactedValue}, ev.ResponseHeaders["Set-Cookie"])
	assert.Equal(t, []string{"application/json"}, ev.ResponseHeaders["Content-Type"])
	// the attempt's own headers are left untouched
	assert.Equal(t, "Bearer secret-token", req.Header.Get("Authorization"))
}

func TestNewHTTPEvidenceTruncatesLargeBodies(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "http://localhost:8080/", nil)
	largeBody := strings.Repeat("a", finding.MaxEvidenceBodySize+1)
	attempt := &finding.Attempt{
		Request:     req,
		RequestBody: []byte(largeBody),
		Response:    &finding.Response{StatusCode: http.StatusOK, Body: bytes.NewBufferString(largeBody)},
	}

	ev := finding.NewHTTPEvidence(attempt)

	require.NotNil(t, ev)
	assert.True(t, strings.HasPrefix(string(ev.RequestBody), largeBody[:finding.MaxEvidenceBodySize]))
	assert.Less(t, len(ev.RequestBody), len(largeBody)+len("... (truncated)"))
	assert.True(t, strings.HasSuffix(string(ev.ResponseBody), "(truncated)"))
}
