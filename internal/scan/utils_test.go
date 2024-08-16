package scan_test

import (
	"net/http"
	"testing"

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
		resp := &http.Response{
			StatusCode: tc.statusCode,
		}
		b := scan.IsUnauthorizedStatusCodeOrSimilar(resp)
		assert.Equal(t, tc.expected, b)
	}
}
