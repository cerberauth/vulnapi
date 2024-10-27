package scan_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/stretchr/testify/assert"
)

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
		res, _ := request.NewResponse(&http.Response{
			Body:       io.NopCloser(bytes.NewBufferString("")),
			StatusCode: tc.statusCode,
		})
		b := scan.IsUnauthorizedStatusCodeOrSimilar(res)
		assert.Equal(t, tc.expected, b)
	}
}
