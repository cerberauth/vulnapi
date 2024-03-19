package jwt_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/scan/jwt"
	"github.com/stretchr/testify/assert"
)

func TestShouldBeScannedWithNoSecurityScheme(t *testing.T) {
	result := jwt.ShouldBeScanned(nil)
	assert.False(t, result, "Expected false when securitySheme is nil")
}

func TestShouldBeScannedWithInvalidToken(t *testing.T) {
	securitySheme := auth.NewAuthorizationBearerSecurityScheme("token", nil)
	result := jwt.ShouldBeScanned(securitySheme)
	assert.False(t, result, "Expected false when securitySheme.GetValidValueWriter() is nil")
}

func TestShouldBeScannedWithInvalidWriter(t *testing.T) {
	securitySheme := auth.NewNoAuthSecurityScheme()
	result := jwt.ShouldBeScanned(securitySheme)
	assert.False(t, result, "Expected false when securitySheme.GetValidValueWriter() is not a JWTWriter")
}

func TestShouldBeScannedWithValidWriter(t *testing.T) {
	// Test case 1: securitySheme is nil
	result := jwt.ShouldBeScanned(nil)
	assert.False(t, result, "Expected false when securitySheme is nil")
}
