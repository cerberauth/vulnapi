package scan

import (
	"errors"
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
)

type VulnerabilityScanAttempt struct {
	Request  *http.Request
	Response *http.Response
	Err      error
}

func ScanURL(operation *request.Operation, securityScheme *auth.SecurityScheme) (*VulnerabilityScanAttempt, error) {
	req, err := operation.NewRequest()
	if err != nil {
		return nil, errors.New("request has an unexpected error")
	}

	if securityScheme != nil {
		req.WithSecurityScheme(*securityScheme)
	} else if len(operation.GetSecuritySchemes()) > 0 {
		req.WithSecurityScheme(operation.GetSecuritySchemes()[0])
	}

	resp, err := req.Do()
	if err != nil {
		return nil, errors.New("request has an unexpected error")
	}
	defer resp.Body.Close()

	return &VulnerabilityScanAttempt{
		Request:  req.Request,
		Response: resp,
		Err:      err,
	}, nil
}
