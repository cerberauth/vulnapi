package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewNoAuthSecurityScheme(t *testing.T) {
	securityScheme, err := auth.NewNoAuthSecurityScheme()

	assert.NoError(t, err)
	assert.NotNil(t, securityScheme)
	assert.Equal(t, "no_auth", securityScheme.GetName())
	assert.Equal(t, auth.None, securityScheme.GetType())
	assert.Equal(t, auth.NoneScheme, securityScheme.GetScheme())
	assert.Nil(t, securityScheme.GetIn())
}

func TestMustNewNoAuthSecurityScheme(t *testing.T) {
	securityScheme := auth.MustNewNoAuthSecurityScheme()

	assert.NotNil(t, securityScheme)
	assert.Equal(t, "no_auth", securityScheme.GetName())
	assert.Equal(t, auth.None, securityScheme.GetType())
	assert.Equal(t, auth.NoneScheme, securityScheme.GetScheme())
	assert.Nil(t, securityScheme.GetIn())
}
