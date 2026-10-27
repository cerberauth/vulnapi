package scenario

import (
	"crypto/tls"
	"encoding/base64"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
)

// apiKeyHeaders are well-known API key header names, checked in this order
// before falling back to apiKeyKeywords.
var apiKeyHeaders = []string{
	"X-Api-Key",
	"Api-Key",
	"Apikey",
	"X-Apikey",
	"X-Api-Token",
	"X-Auth-Token",
	"X-Access-Token",
	"X-Token",
	"X-App-Key",
	"App-Key",
	"X-Api-Secret",
	"Api-Secret",
}

var apiKeyKeywords = []string{"key", "token", "secret"}

// nonCredentialHeaders contain an apiKeyKeywords keyword but never carry
// an API key.
var nonCredentialHeaders = []string{
	"Sec-Websocket-Key",
	"Sec-Websocket-Accept",
	"Idempotency-Key",
	"X-Idempotency-Key",
	"X-Csrf-Token",
	"X-Xsrf-Token",
	"Csrf-Token",
}

func detectAuthorizationHeader(header http.Header) string {
	if h := header.Get(auth.AuthorizationHeader); h != "" {
		return h
	}

	// header may hold non-canonical keys when not built with Set or Add
	for name, values := range header {
		if strings.EqualFold(name, auth.AuthorizationHeader) && len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

// splitAuthorization splits an Authorization header value into its scheme
// and credentials.
func splitAuthorization(authHeader string) (string, string) {
	scheme, credentials, ok := strings.Cut(strings.TrimSpace(authHeader), " ")
	if !ok {
		return "", ""
	}
	return scheme, strings.TrimSpace(credentials)
}

// getAuthorizationCredentials returns the credentials of authHeader when it
// uses scheme. Auth schemes are case-insensitive (RFC 9110 §11.1).
func getAuthorizationCredentials(authHeader string, scheme string) string {
	headerScheme, credentials := splitAuthorization(authHeader)
	if !strings.EqualFold(headerScheme, scheme) {
		return ""
	}
	return credentials
}

func getBearerToken(authHeader string) string {
	return getAuthorizationCredentials(authHeader, auth.BearerPrefix)
}

func getHttpBasicAuthUser(authHeader string) string {
	return getAuthorizationCredentials(authHeader, auth.BasicPrefix)
}

func detectAPIKeyHeader(header http.Header) (string, string) {
	for _, name := range apiKeyHeaders {
		if value := header.Get(name); value != "" {
			return name, value
		}
	}

	// Fall back to any header whose name contains a keyword, in a stable
	// order.
	names := slices.Sorted(maps.Keys(header))
	for _, name := range names {
		if slices.Contains(nonCredentialHeaders, http.CanonicalHeaderKey(name)) || len(header[name]) == 0 || header[name][0] == "" {
			continue
		}
		for _, keyword := range apiKeyKeywords {
			if strings.Contains(strings.ToLower(name), keyword) {
				return name, header[name][0]
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
