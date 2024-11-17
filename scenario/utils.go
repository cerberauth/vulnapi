package scenario

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
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

func detectSecurityScheme(header http.Header) (*auth.SecurityScheme, error) {
	authHeader := detectAuthorizationHeader(header)
	if authHeader == "" {
		return nil, nil
	}

	token := getBearerToken(authHeader)
	if token == "" {
		return nil, fmt.Errorf("empty authorization header")
	}

	return auth.NewAuthorizationBearerSecurityScheme("default", &token)
}

func addDefaultProtocolWhenMissing(url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	return url
}
