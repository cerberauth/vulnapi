package scan

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const bearerPrefix = auth.BearerPrefix + " "

func detectAuthorizationHeader(headers *http.Header) string {
	if h := headers.Get(auth.AuthorizationHeader); h != "" {
		return h
	}

	if h := headers.Get(strings.ToLower(auth.AuthorizationHeader)); h != "" {
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

func detectSecurityScheme(headers *http.Header, cookies []http.Cookie) auth.SecurityScheme {
	if authHeader := detectAuthorizationHeader(headers); authHeader != "" {
		if token := getBearerToken(authHeader); token != "" {
			return auth.NewAuthorizationBearerSecurityScheme("default", &token)
		}
	}

	return nil
}

func NewURLScan(method string, url string, headers *http.Header, cookies []http.Cookie, reporter *report.Reporter) (*Scan, error) {
	var securitySchemes []auth.SecurityScheme
	if securityScheme := detectSecurityScheme(headers, cookies); securityScheme != nil {
		securitySchemes = append(securitySchemes, securityScheme)
	}

	operations := request.Operations{{
		Url:     url,
		Method:  method,
		Headers: headers,
		Cookies: cookies,

		SecuritySchemes: securitySchemes,
	}}

	return NewScan(operations, reporter)
}
