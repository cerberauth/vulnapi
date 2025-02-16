package scan

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
)

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
	return NewIssueScanAttempt(operation, req, res, err), err
}
