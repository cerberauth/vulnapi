package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthorizationBearerSecurityScheme(t *testing.T) {
	name := "token"
	value := "abc123"
	tokenFormat := auth.NoneTokenFormat

	securityScheme, err := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	assert.NoError(t, err)
	assert.Equal(t, auth.HttpType, securityScheme.GetType())
	assert.Equal(t, auth.BearerScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, value, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestNewAuthorizationBearerSecurityScheme_WhenNilValue(t *testing.T) {
	name := "token"

	securityScheme, err := auth.NewAuthorizationBearerSecurityScheme(name, nil)

	assert.NoError(t, err)
	assert.Nil(t, securityScheme.GetTokenFormat())
	assert.Equal(t, nil, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestNewAuthorizationBearerSecurityScheme_WhenJWTFormatValue(t *testing.T) {
	name := "token"
	value := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ufhxDTmrs4T5MSsvT6lsb3OpdWi5q8O31VX7TgrVamA"
	tokenFormat := auth.JWTTokenFormat

	securityScheme, err := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	assert.NoError(t, err)
	assert.Equal(t, auth.HttpType, securityScheme.GetType())
	assert.Equal(t, auth.BearerScheme, securityScheme.GetScheme())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, value, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestMustNewAuthorizationBearerSecurityScheme(t *testing.T) {
	name := "token"
	value := "abc123"
	tokenFormat := auth.NoneTokenFormat

	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme(name, &value)

	assert.Equal(t, auth.HttpType, securityScheme.GetType())
	assert.Equal(t, auth.BearerScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, value, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}
