package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/jwt"
)

func ShouldBeScanned(securitySheme auth.SecurityScheme) bool {
	if securitySheme == nil || securitySheme.GetValidValueWriter() == nil {
		return false
	}

	if token, ok := securitySheme.GetValidValueWriter().(*jwt.JWTWriter); !ok || token == nil {
		return false
	}

	return true
}
