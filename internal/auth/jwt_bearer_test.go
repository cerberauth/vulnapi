package auth_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthorizationJWTBearerSecurityScheme(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	assert.NoError(t, err)
	assert.Equal(t, auth.HttpType, ss.Type)
	assert.Equal(t, auth.BearerScheme, ss.Scheme)
	assert.Equal(t, auth.InHeader, ss.In)
	assert.Equal(t, name, ss.Name)
	assert.Equal(t, &value, ss.ValidValue)
	assert.Equal(t, "", ss.AttackValue)
}

func TestNewAuthorizationJWTBearerSecuritySchemeWithInvalidJWT(t *testing.T) {
	name := "token"
	value := "abc123"
	_, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	assert.Error(t, err)
}

func TestJWTBearerSecurityScheme_GetHeaders(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	attackValue := "xyz789"
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	ss.SetAttackValue(attackValue)

	headers := ss.GetHeaders()

	assert.NoError(t, err)
	assert.Equal(t, http.Header{
		"Authorization": []string{"Bearer xyz789"},
	}, headers)
}

func TestJWTBearerSecurityScheme_GetCookies(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	cookies := ss.GetCookies()

	assert.NoError(t, err)
	assert.Empty(t, cookies)
}

func TestJWTBearerSecurityScheme_HasValidValue(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	hasValidValue := ss.HasValidValue()

	assert.NoError(t, err)
	assert.True(t, hasValidValue)
}

func TestJWTBearerSecurityScheme_HasValidValue_WhenNoValue(t *testing.T) {
	name := "token"
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, nil)
	hasValidValue := ss.HasValidValue()

	assert.NoError(t, err)
	assert.False(t, hasValidValue)
}

func TestJWTBearerSecurityScheme_GetValidValue(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	validValue := ss.GetValidValue()

	assert.NoError(t, err)
	assert.Equal(t, value, validValue)
}

func TestJWTBearerSecurityScheme_GetValidValueWriter(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	writer := ss.GetValidValueWriter()

	assert.NoError(t, err)
	assert.Equal(t, ss.JWTWriter, writer)
}

func TestJWTBearerSecurityScheme_SetAttackValue(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	attackValue := "xyz789"
	ss.SetAttackValue(attackValue)

	assert.NoError(t, err)
	assert.Equal(t, attackValue, ss.AttackValue)
}

func TestJWTBearerSecurityScheme_GetAttackValue(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)
	attackValue := "xyz789"
	ss.SetAttackValue(attackValue)

	result := ss.GetAttackValue()

	assert.NoError(t, err)
	assert.Equal(t, attackValue, result)
}
