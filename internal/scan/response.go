package scan

import (
	"fmt"
	"net/http"
)

func DetectNotExpectedResponse(resp *http.Response) error {
	if resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusInternalServerError {
		return nil
	}

	return fmt.Errorf("unexpected response: %d", resp.StatusCode)
}
