package scan

import (
	"errors"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

func ScanURL(operation *request.Operation, securityScheme *auth.SecurityScheme) (*report.VulnerabilityScanAttempt, error) {
	req, err := request.NewRequest(operation.Client, operation.Method, operation.Request.URL.String(), nil)
	if err != nil {
		return nil, errors.New("request has an unexpected error")
	}

	req = req.WithSecurityScheme(securityScheme)
	resp, err := req.Do()
	if err != nil {
		return nil, errors.New("request has an unexpected error")
	}
	defer resp.Body.Close()

	return &report.VulnerabilityScanAttempt{
		Request:  req.Request,
		Response: resp,
		Err:      err,
	}, nil
}
