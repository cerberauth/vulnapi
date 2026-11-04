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

	securityScheme, err := detectSecurityScheme(header)

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
