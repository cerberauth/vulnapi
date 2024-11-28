package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestGetSecuritySchemeUniqueName(t *testing.T) {
	tests := []struct {
		name           string
		securityScheme *auth.SecurityScheme
		expected       string
	}{
		{
			name:           "no auth security scheme",
			securityScheme: auth.MustNewNoAuthSecurityScheme(),
			expected:       "none-None",
		},
		{
			name:           "bearer security scheme",
			securityScheme: auth.MustNewAuthorizationBearerSecurityScheme("name", nil),
			expected:       "http-Bearer-header",
		},
		{
			name:           "oauth security scheme",
			securityScheme: auth.MustNewOAuthSecurityScheme("name", nil, &auth.OAuthValue{}, nil),
			expected:       "oauth2-OAuth-header",
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
