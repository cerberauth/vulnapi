package scan

import (
	"net/http"
)

func IsUnauthorizedStatusCodeOrSimilar(resp *http.Response) bool {
	return resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusBadRequest ||
		resp.StatusCode == http.StatusNotFound ||
		resp.StatusCode == http.StatusInternalServerError
}
