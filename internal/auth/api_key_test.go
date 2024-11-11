package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewAPIKeySecurityScheme(t *testing.T) {
	name := "token"
	value := "abc123"
	tokenFormat := auth.NoneTokenFormat

	securityScheme, err := auth.NewAPIKeySecurityScheme(name, auth.InHeader, &value)

	assert.NoError(t, err)
	assert.Equal(t, auth.ApiKey, securityScheme.GetType())
	assert.Equal(t, auth.NoneScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, value, securityScheme.GetValidValue().(string))
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestTestNewAPIKeySecurityScheme_WhenNilValue(t *testing.T) {
	name := "token"

	securityScheme, err := auth.NewAPIKeySecurityScheme(name, auth.InHeader, nil)

	assert.NoError(t, err)
	assert.Equal(t, nil, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestNewAuthorizationBearerSecurityScheme_WhenInCooke(t *testing.T) {
	name := "token"
	value := "abc123"

	securityScheme, err := auth.NewAPIKeySecurityScheme(name, auth.InQuery, &value)

	assert.NoError(t, err)
	assert.Equal(t, auth.InQuery, *securityScheme.GetIn())
}

func TestMustNewAPIKeySecurityScheme(t *testing.T) {
	name := "token"
	value := "abc123"
	tokenFormat := auth.NoneTokenFormat

	securityScheme := auth.MustNewAPIKeySecurityScheme(name, auth.InHeader, &value)

	assert.Equal(t, auth.ApiKey, securityScheme.GetType())
	assert.Equal(t, auth.NoneScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, value, securityScheme.GetValidValue().(string))
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}
