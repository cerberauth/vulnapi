package jwt

import (
	"github.com/cerberauth/vulnapi/internal/auth"
)

const fakeJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

func ShouldBeScanned(securitySheme auth.SecurityScheme) bool {
	if securitySheme == nil {
		return false
	}

	if _, ok := securitySheme.(*auth.JWTBearerSecurityScheme); !ok {
		return false
	}

	return true
}
