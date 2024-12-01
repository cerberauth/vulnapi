package scenario

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
)

const bearerPrefix = auth.BearerPrefix + " "

var apiKeyKeywords = []string{"key", "token", "secret"}

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

func detectAPIKeyHeader(header http.Header) (string, string) {
	for headerName, headerValue := range header {
		for _, keyword := range apiKeyKeywords {
			if strings.Contains(strings.ToLower(headerName), keyword) {
				return headerName, headerValue[0]
			}
		}
	}

	return "", ""
}

func detectSecurityScheme(header http.Header) (*auth.SecurityScheme, error) {
	authHeader := detectAuthorizationHeader(header)
	if authHeader != "" {
		if token := getBearerToken(authHeader); token != "" {
			return auth.NewAuthorizationBearerSecurityScheme("default", &token)
		}

		return auth.NewAPIKeySecurityScheme(auth.AuthorizationHeader, auth.InHeader, &authHeader)
	}

	if headerName, headerValue := detectAPIKeyHeader(header); headerName != "" {
		return auth.NewAPIKeySecurityScheme(headerName, auth.InHeader, &headerValue)
	}

	return nil, nil
}

func addDefaultProtocolWhenMissing(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return url
}
