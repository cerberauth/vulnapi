package scenario

import (
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
)

const bearerPrefix = auth.BearerPrefix + " "
const basicPrefix = auth.BasicPrefix + " "

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

func getHttpBasicAuthUser(authHeader string) string {
	if strings.HasPrefix(authHeader, basicPrefix) {
		return strings.TrimPrefix(authHeader, basicPrefix)
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

func decodeBasicAuth(encodedUser string) (string, string) {
	decoded, err := base64.StdEncoding.DecodeString(encodedUser)
	if err != nil {
		return "", ""
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	return parts[0], parts[1]
}

func detectSecurityScheme(header http.Header) (*auth.SecurityScheme, error) {
	authHeader := detectAuthorizationHeader(header)
	if authHeader != "" {
		if token := getBearerToken(authHeader); token != "" {
			return auth.NewAuthorizationBearerSecurityScheme("default", &token)
		} else if encodedUser := getHttpBasicAuthUser(authHeader); encodedUser != "" {
			username, password := decodeBasicAuth(encodedUser)
			return auth.NewAuthorizationBasicSecurityScheme("default", auth.NewHTTPBasicCredentials(username, password))
		}

		return auth.NewAPIKeySecurityScheme(auth.AuthorizationHeader, auth.InHeader, &authHeader)
	}

	if headerName, headerValue := detectAPIKeyHeader(header); headerName != "" {
		return auth.NewAPIKeySecurityScheme(headerName, auth.InHeader, &headerValue)
	}

	return nil, nil
}

func addDefaultProtocolWhenMissing(u *url.URL) *url.URL {
	if u.Scheme != "" {
		return u
	}

	tlsConn, err := tls.Dial("tcp", u.String(), nil)
	if err == nil {
		defer tlsConn.Close()
		u.Scheme = "https"
	} else {
		u.Scheme = "http"
	}
	return u
}
