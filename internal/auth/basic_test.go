package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthorizationBasicSecurityScheme(t *testing.T) {
	name := "basic"
	basicCredentials := auth.NewHTTPBasicCredentials("admin", "password")

	securityScheme, err := auth.NewAuthorizationBasicSecurityScheme(name, basicCredentials)

	assert.NoError(t, err)
	assert.Equal(t, auth.HttpType, securityScheme.GetType())
	assert.Equal(t, auth.BasicScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, basicCredentials, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestNewAuthorizationBasicSecurityScheme_WhenNilValue(t *testing.T) {
	name := "basic"

	securityScheme, err := auth.NewAuthorizationBasicSecurityScheme(name, nil)

	assert.NoError(t, err)
	assert.Equal(t, nil, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestMustNewAuthorizationBasicSecurityScheme(t *testing.T) {
	name := "basic"
	basicCredentials := auth.NewHTTPBasicCredentials("admin", "password")

	securityScheme := auth.MustNewAuthorizationBasicSecurityScheme(name, basicCredentials)

	assert.Equal(t, auth.HttpType, securityScheme.GetType())
	assert.Equal(t, auth.BasicScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, basicCredentials, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}
