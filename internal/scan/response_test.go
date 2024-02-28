package scan_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/stretchr/testify/assert"
)

func TestDetectNotExpectedResponse(t *testing.T) {
	testCases := []struct {
		statusCode int
		expected   error
	}{
		{http.StatusUnauthorized, nil},
		{http.StatusForbidden, nil},
		{http.StatusNotFound, nil},
		{http.StatusInternalServerError, nil},
		{http.StatusOK, fmt.Errorf("unexpected response: %d", http.StatusOK)},
		{http.StatusBadGateway, fmt.Errorf("unexpected response: %d", http.StatusBadGateway)},
	}

	for _, tc := range testCases {
		resp := &http.Response{
			StatusCode: tc.statusCode,
		}

		err := scan.DetectNotExpectedResponse(resp)

		assert.Equal(t, tc.expected, err)
	}
}
