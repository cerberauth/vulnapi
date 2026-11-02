package finding_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test", "value")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("body"))
	}))
	defer server.Close()

	op := operation.MustNewOperation(http.MethodGet, server.URL, nil, nil)

	attempt, err := finding.Fetch(context.Background(), op, nil)

	require.NoError(t, err)
	require.NotNil(t, attempt.Response)
	assert.Equal(t, http.StatusTeapot, attempt.Response.GetStatusCode())
	assert.Equal(t, "value", attempt.Response.GetHeader().Get("X-Test"))
	assert.Equal(t, "body", attempt.Response.GetBody().String())
	assert.NoError(t, attempt.Err)
}

func TestFetchReturnsAttemptOnTransportError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	op := operation.MustNewOperation(http.MethodGet, url, nil, nil)

	attempt, err := finding.Fetch(context.Background(), op, nil)

	require.Error(t, err)
	require.NotNil(t, attempt)
	assert.Nil(t, attempt.Response)
	assert.Equal(t, err, attempt.Err)
}

func TestIsUnauthorizedStatusCodeOrSimilar(t *testing.T) {
	testCases := []struct {
		statusCode int
		expected   bool
	}{
		{http.StatusUnauthorized, true},
		{http.StatusForbidden, true},
		{http.StatusBadRequest, true},
		{http.StatusNotFound, true},
		{http.StatusInternalServerError, true},
		{http.StatusOK, false},
		{http.StatusBadGateway, false},
	}

	for _, tc := range testCases {
		res := &finding.Response{StatusCode: tc.statusCode}
		b := finding.IsUnauthorizedStatusCodeOrSimilar(res)
		assert.Equal(t, tc.expected, b)
	}
}
