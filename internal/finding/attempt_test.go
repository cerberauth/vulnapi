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

func TestFetchWithoutRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer server.Close()

	op := operation.MustNewOperation(http.MethodGet, server.URL+"/profile", nil, nil)

	attempt, err := finding.FetchWithoutRedirect(context.Background(), op, nil)

	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, attempt.Response.GetStatusCode())
	assert.Equal(t, "/login", attempt.Response.GetHeader().Get("Location"))
}

func TestIsRejected(t *testing.T) {
	jsonHeader := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}
	htmlHeader := http.Header{"Content-Type": []string{"text/html"}}
	loginRedirect := http.Header{"Location": []string{"/login"}}

	testCases := []struct {
		name     string
		res      *finding.Response
		baseline *finding.Response
		expected bool
	}{
		{"unauthorized", &finding.Response{StatusCode: http.StatusUnauthorized}, nil, true},
		{"ok without baseline", &finding.Response{StatusCode: http.StatusOK, Header: jsonHeader}, nil, false},
		{"same content as baseline", &finding.Response{StatusCode: http.StatusOK, Header: jsonHeader}, &finding.Response{StatusCode: http.StatusOK, Header: jsonHeader}, false},
		{"catch-all html page", &finding.Response{StatusCode: http.StatusOK, Header: htmlHeader}, &finding.Response{StatusCode: http.StatusOK, Header: jsonHeader}, true},
		{"login redirect", &finding.Response{StatusCode: http.StatusFound, Header: loginRedirect}, &finding.Response{StatusCode: http.StatusOK, Header: jsonHeader}, true},
		{"login redirect without baseline", &finding.Response{StatusCode: http.StatusSeeOther, Header: loginRedirect}, nil, true},
		{"same redirect as baseline", &finding.Response{StatusCode: http.StatusFound, Header: loginRedirect}, &finding.Response{StatusCode: http.StatusFound, Header: loginRedirect}, false},
		{"rejected baseline", &finding.Response{StatusCode: http.StatusOK, Header: htmlHeader}, &finding.Response{StatusCode: http.StatusUnauthorized, Header: jsonHeader}, false},
		{"no response", nil, nil, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, finding.IsRejected(tc.res, tc.baseline))
		})
	}
}
