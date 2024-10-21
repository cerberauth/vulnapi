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

func TestMustNewAuthorizationJWTBearerSecurityScheme(t *testing.T) {
	t.Run("ValidJWT", func(t *testing.T) {
		name := "token"
		value := jwt.FakeJWT
		ss := auth.MustNewAuthorizationJWTBearerSecurityScheme(name, &value)

		assert.NotNil(t, ss)
		assert.Equal(t, auth.HttpType, ss.Type)
		assert.Equal(t, auth.BearerScheme, ss.Scheme)
		assert.Equal(t, auth.InHeader, ss.In)
		assert.Equal(t, name, ss.Name)
		assert.Equal(t, &value, ss.ValidValue)
		assert.Equal(t, "", ss.AttackValue)
	})

	t.Run("InvalidJWT", func(t *testing.T) {
		name := "token"
		value := "abc123"
		assert.Panics(t, func() {
			auth.MustNewAuthorizationJWTBearerSecurityScheme(name, &value)
		})
	})

	t.Run("NilValue", func(t *testing.T) {
		name := "token"
		ss := auth.MustNewAuthorizationJWTBearerSecurityScheme(name, nil)

		assert.NotNil(t, ss)
		assert.Equal(t, auth.HttpType, ss.Type)
		assert.Equal(t, auth.BearerScheme, ss.Scheme)
		assert.Equal(t, auth.InHeader, ss.In)
		assert.Equal(t, name, ss.Name)
		assert.Nil(t, ss.ValidValue)
		assert.Equal(t, "", ss.AttackValue)
	})
}

func TestAuthorizationJWTBearerSecurityScheme_GetScheme(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	scheme := ss.GetScheme()

	assert.NoError(t, err)
	assert.Equal(t, auth.BearerScheme, scheme)
}

func TestAuthorizationJWTBearerSecurityScheme_GetType(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	scheme := ss.GetType()

	assert.NoError(t, err)
	assert.Equal(t, auth.HttpType, scheme)
}

func TestAuthorizationJWTBearerSecurityScheme_GetIn(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	scheme := ss.GetIn()

	assert.NoError(t, err)
	assert.Equal(t, auth.InHeader, *scheme)
}

func TestAuthorizationJWTBearerSecurityScheme_GetName(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	scheme := ss.GetName()

	assert.NoError(t, err)
	assert.Equal(t, name, scheme)
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

func TestJWTBearerSecurityScheme_GetHeaders_WhenNoAttackValue(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, &value)

	headers := ss.GetHeaders()

	assert.NoError(t, err)
	assert.Equal(t, http.Header{
		"Authorization": []string{"Bearer " + jwt.FakeJWT},
	}, headers)
}

func TestJWTBearerSecurityScheme_GetHeaders_WhenNoAttackAndValidValue(t *testing.T) {
	name := "token"
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, nil)

	headers := ss.GetHeaders()

	assert.NoError(t, err)
	assert.Equal(t, http.Header{}, headers)
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

func TestJWTBearerSecurityScheme_GetValidValue_WhenNoValue(t *testing.T) {
	name := "token"
	ss, err := auth.NewAuthorizationJWTBearerSecurityScheme(name, nil)
	validValue := ss.GetValidValue()

	assert.NoError(t, err)
	assert.Nil(t, validValue)
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
