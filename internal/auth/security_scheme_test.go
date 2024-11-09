package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestGetSecuritySchemeUniqueName(t *testing.T) {
	noAuthSecurityScheme := auth.NewNoAuthSecurityScheme()
	bearerSecurityScheme := auth.NewAuthorizationBearerSecurityScheme("name", nil)
	jwtBearerSecurityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("name", nil)
	oauthSecurityScheme := auth.NewOAuthSecurityScheme("name", nil, nil)

	tests := []struct {
		name           string
		securityScheme auth.SecurityScheme
		expected       string
	}{
		{
			name:           "no auth security scheme",
			securityScheme: noAuthSecurityScheme,
			expected:       "none-None",
		},
		{
			name:           "bearer security scheme",
			securityScheme: bearerSecurityScheme,
			expected:       "http-Bearer-header",
		},
		{
			name:           "jwt bearer security scheme",
			securityScheme: jwtBearerSecurityScheme,
			expected:       "http-Bearer-header",
		},
		{
			name:           "oauth security scheme",
			securityScheme: oauthSecurityScheme,
			expected:       "oauth2-Bearer-header",
		},
	}

	assert.Equal(t, "", auth.GetSecuritySchemeUniqueName(nil))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.GetSecuritySchemeUniqueName(tt.securityScheme)
			assert.Equal(t, tt.expected, result)
		})
	}
}
