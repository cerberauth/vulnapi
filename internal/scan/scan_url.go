package scan

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
)

type IssueScanAttempt struct {
	Request  *request.Request
	Response *request.Response
	Err      error
}

func ScanURL(operation *operation.Operation, securityScheme *auth.SecurityScheme) (*IssueScanAttempt, error) {
	req, err := operation.NewRequest()
	if err != nil {
		return nil, err
	}

	if securityScheme != nil {
		req.WithSecurityScheme(securityScheme)
	} else {
		req.WithSecurityScheme(operation.GetSecurityScheme())
	}

	res, err := req.Do()
	return &IssueScanAttempt{
		Request:  req,
		Response: res,
		Err:      err,
	}, err
}
