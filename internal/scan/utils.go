package scan

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/request"
)

func IsUnauthorizedStatusCodeOrSimilar(resp *request.Response) bool {
	return resp.GetStatusCode() == http.StatusUnauthorized ||
		resp.GetStatusCode() == http.StatusForbidden ||
		resp.GetStatusCode() == http.StatusBadRequest ||
		resp.GetStatusCode() == http.StatusNotFound ||
		resp.GetStatusCode() == http.StatusInternalServerError
}
