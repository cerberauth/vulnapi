package scan

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const bearerPrefix = auth.BearerPrefix + " "

func detectAuthorizationHeader(header http.Header) string {
	if h := header.Get(auth.AuthorizationHeader); h != "" {
		return h
	}

	if h := header.Get(strings.ToLower(auth.AuthorizationHeader)); h != "" {
		return h
	}

	return ""
}

func getBearerToken(authHeader string) string {
	if strings.HasPrefix(authHeader, bearerPrefix) {
		return strings.TrimPrefix(authHeader, bearerPrefix)
	}

	lowerCasePrefix := strings.ToLower(bearerPrefix)
	if strings.HasPrefix(authHeader, lowerCasePrefix) {
		return strings.TrimPrefix(authHeader, lowerCasePrefix)
	}

	return ""
}

func detectSecurityScheme(header http.Header) auth.SecurityScheme {
	if authHeader := detectAuthorizationHeader(header); authHeader != "" {
		if token := getBearerToken(authHeader); token != "" {
			return auth.NewAuthorizationBearerSecurityScheme("default", &token)
		}
	}

	return nil
}

func NewURLScan(method string, url string, header http.Header, cookies []http.Cookie, reporter *report.Reporter) (*Scan, error) {
	var securitySchemes []auth.SecurityScheme
	if securityScheme := detectSecurityScheme(header); securityScheme != nil {
		securitySchemes = append(securitySchemes, securityScheme)
	} else {
		securitySchemes = append(securitySchemes, auth.NewNoAuthSecurityScheme())
	}

	operations := request.Operations{request.NewOperation(url, method, header, cookies, securitySchemes)}

	return NewScan(operations, reporter)
}
