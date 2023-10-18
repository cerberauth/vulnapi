package restapi

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

func ScanRestAPI(url string, token string) *report.VulnerabilityScanAttempt {
	req, resp, err := request.SendRequestWithBearerAuth(url, token)
	if err != nil {
		err = fmt.Errorf("request with url %s has an unexpected error", err)
	}

	if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		err = fmt.Errorf("unexpected status code %d during test request", resp.StatusCode)
	}

	return &report.VulnerabilityScanAttempt{
		Request:  req,
		Response: resp,
		Err:      err,
	}
}
