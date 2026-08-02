package finding_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/finding"
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
		res := &finding.Response{StatusCode: tc.statusCode}
		b := finding.IsUnauthorizedStatusCodeOrSimilar(res)
		assert.Equal(t, tc.expected, b)
	}
}
