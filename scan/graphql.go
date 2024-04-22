package scan

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

func NewGraphQLScan(url string, header http.Header, cookies []http.Cookie, reporter *report.Reporter) (*Scan, error) {
	var securitySchemes []auth.SecurityScheme
	securityScheme, err := detectSecurityScheme(header)
	if err != nil {
		return nil, err
	}

	if securityScheme != nil {
		securitySchemes = append(securitySchemes, securityScheme)
	} else {
		securitySchemes = append(securitySchemes, auth.NewNoAuthSecurityScheme())
	}

	operations := request.Operations{request.NewOperation(url, http.MethodPost, header, cookies, securitySchemes)}

	return NewScan(operations, reporter)
}
