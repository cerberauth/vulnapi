package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

func ScanURL(operation *request.Operation, securityScheme *auth.SecurityScheme) (*report.VulnerabilityScanAttempt, error) {
	req, err := request.NewRequest(operation.Method, operation.Url, nil)
	if err != nil {
		return nil, fmt.Errorf("request with url %s has an unexpected error", err)
	} else {
		req = req.WithSecurityScheme(securityScheme)
	}

	resp, err := req.Do()
	if err != nil {
		err = fmt.Errorf("request with url %s has an unexpected error", err)
	} else if resp.StatusCode < 200 && resp.StatusCode >= 300 {
		err = fmt.Errorf("unexpected status code %d during test request", resp.StatusCode)
	}
	defer resp.Body.Close()

	return &report.VulnerabilityScanAttempt{
		Request:  req.Request,
		Response: resp,
		Err:      err,
	}, nil
}
