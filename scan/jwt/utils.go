package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
)

func ShouldBeScanned(securitySheme auth.SecurityScheme) bool {
	if securitySheme == nil {
		return false
	}

	if _, ok := securitySheme.(*auth.JWTBearerSecurityScheme); !ok {
		return false
	}

	return true
}
