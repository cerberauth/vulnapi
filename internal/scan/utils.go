package scan

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/request"
)

func IsUnauthorizedStatusCodeOrSimilar(res *request.Response) bool {
	return res.GetStatusCode() == http.StatusUnauthorized ||
		res.GetStatusCode() == http.StatusForbidden ||
		res.GetStatusCode() == http.StatusBadRequest ||
		res.GetStatusCode() == http.StatusNotFound ||
		res.GetStatusCode() == http.StatusInternalServerError
}
