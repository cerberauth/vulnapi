package scenario

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestGetBearerToken(t *testing.T) {
	assert.Equal(t, "token", getBearerToken("Bearer token"))
	assert.Equal(t, "token", getBearerToken("bearer token"))
	assert.Equal(t, "token", getBearerToken("BEARER  token "))
	assert.Equal(t, "", getBearerToken("Basic dXNlcjpwYXNzd29yZA=="))
	assert.Equal(t, "", getBearerToken("Bearer"))
}

func TestGetHttpBasicAuthUser(t *testing.T) {
	assert.Equal(t, "dXNlcjpwYXNzd29yZA==", getHttpBasicAuthUser("Basic dXNlcjpwYXNzd29yZA=="))
	assert.Equal(t, "dXNlcjpwYXNzd29yZA==", getHttpBasicAuthUser("basic dXNlcjpwYXNzd29yZA=="))
	assert.Equal(t, "", getHttpBasicAuthUser("bearer token"))
}

func TestDetectSecuritySchemeWithLowercaseBasicAuth(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "basic dXNlcjpwYXNzd29yZA==")

	securityScheme, err := detectSecurityScheme(header, nil)

	assert.NoError(t, err)
	assert.Equal(t, auth.BasicScheme, securityScheme.GetScheme())
}

func TestDetectAuthorizationHeaderWithNonCanonicalKey(t *testing.T) {
	header := http.Header{"authorization": []string{"Bearer token"}}

	assert.Equal(t, "Bearer token", detectAuthorizationHeader(header))
}

func TestDetectAPIKeyHeader(t *testing.T) {
	tests := []struct {
		name          string
		header        http.Header
		expectedName  string
		expectedValue string
	}{
		{
			name:          "well-known header wins over keyword match",
			header:        http.Header{"X-Custom-Token": []string{"custom"}, "X-Api-Key": []string{"key"}},
			expectedName:  "X-Api-Key",
			expectedValue: "key",
		},
		{
			name:          "keyword match is stable",
			header:        http.Header{"X-B-Token": []string{"b"}, "X-A-Token": []string{"a"}},
			expectedName:  "X-A-Token",
			expectedValue: "a",
		},
		{
			name:   "non-credential headers are ignored",
			header: http.Header{"Sec-Websocket-Key": []string{"ws"}, "X-Csrf-Token": []string{"csrf"}, "Idempotency-Key": []string{"id"}},
		},
		{
			name:   "empty values are ignored",
			header: http.Header{"X-Custom-Token": []string{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 10 {
				name, value := detectAPIKeyHeader(tt.header)
				assert.Equal(t, tt.expectedName, name)
				assert.Equal(t, tt.expectedValue, value)
			}
		})
	}
}

func TestDetectSecuritySchemeFromSessionCookie(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
	tests := []struct {
		name         string
		cookies      []*http.Cookie
		expectedName string
		jwt          bool
	}{
		{"session cookie", []*http.Cookie{{Name: "theme", Value: "dark"}, {Name: "SESSIONID", Value: "abc"}}, "SESSIONID", false},
		{"jwt cookie", []*http.Cookie{{Name: "theme", Value: "dark"}, {Name: "id", Value: jwt}}, "id", true},
		{"csrf cookie only", []*http.Cookie{{Name: "csrf_token", Value: "abc"}}, "", false},
		{"no credential cookie", []*http.Cookie{{Name: "theme", Value: "dark"}}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityScheme, err := detectSecurityScheme(http.Header{}, tt.cookies)

			assert.NoError(t, err)
			if tt.expectedName == "" {
				assert.Nil(t, securityScheme)
				return
			}
			assert.Equal(t, auth.ApiKey, securityScheme.GetType())
			assert.Equal(t, auth.InCookie, *securityScheme.GetIn())
			assert.Equal(t, tt.expectedName, securityScheme.GetName())
			assert.Equal(t, tt.jwt, securityScheme.GetTokenFormat() != nil && *securityScheme.GetTokenFormat() == auth.JWTTokenFormat)
		})
	}
}

func TestDetectSecuritySchemePrefersHeaderOverCookie(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "Bearer token")

	securityScheme, err := detectSecurityScheme(header, []*http.Cookie{{Name: "session", Value: "abc"}})

	assert.NoError(t, err)
	assert.Equal(t, auth.BearerScheme, securityScheme.GetScheme())
}
