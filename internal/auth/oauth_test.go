package auth_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewOAuthSecurityScheme(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	assert.Equal(t, auth.HttpType, ss.Type)
	assert.Equal(t, auth.BearerScheme, ss.Scheme)
	assert.Equal(t, auth.InHeader, ss.In)
	assert.Equal(t, name, ss.Name)
	assert.Equal(t, &value, ss.ValidValue)
	assert.Equal(t, "", ss.AttackValue)
	assert.Nil(t, ss.JWTWriter)
}

func TestNewOAuthSecurityScheme_WithJWT(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	assert.Equal(t, auth.HttpType, ss.Type)
	assert.Equal(t, auth.BearerScheme, ss.Scheme)
	assert.Equal(t, auth.InHeader, ss.In)
	assert.Equal(t, name, ss.Name)
	assert.Equal(t, &value, ss.ValidValue)
	assert.Equal(t, "", ss.AttackValue)
	assert.NotNil(t, ss.JWTWriter)
}

func TestOAuthSecurityScheme_GetScheme(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	scheme := ss.GetScheme()

	assert.Equal(t, auth.BearerScheme, scheme)
}

func TestOAuthSecurityScheme_GetType(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	scheme := ss.GetType()

	assert.Equal(t, auth.HttpType, scheme)
}

func TestOAuthSecurityScheme_GetIn(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	scheme := ss.GetIn()

	assert.Equal(t, auth.InHeader, *scheme)
}

func TestOAuthSecurityScheme_GetName(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	scheme := ss.GetName()

	assert.Equal(t, name, scheme)
}

func TestNewOAuthSecurityScheme_GetHeaders(t *testing.T) {
	name := "token"
	value := "abc123"
	attackValue := "xyz789"

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)
	ss.SetAttackValue(attackValue)

	headers := ss.GetHeaders()

	assert.Equal(t, http.Header{
		"Authorization": []string{"Bearer xyz789"},
		"Cache-Control": []string{"private, max-age=0"},
	}, headers)
}

func TestNewOAuthSecurityScheme_GetHeaders_WhenNoAttackValue(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	headers := ss.GetHeaders()

	assert.Equal(t, http.Header{
		"Authorization": []string{"Bearer abc123"},
		"Cache-Control": []string{"private, max-age=0"},
	}, headers)
}

func TestNewOAuthSecurityScheme_GetHeaders_WhenNoAttackAndValidValue(t *testing.T) {
	name := "token"
	ss := auth.NewOAuthSecurityScheme(name, nil, nil)

	headers := ss.GetHeaders()

	assert.Equal(t, http.Header{
		"Cache-Control": []string{"public, max-age=3600"},
	}, headers)
}

func TestNewOAuthSecurityScheme_GetCookies(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	cookies := ss.GetCookies()

	assert.Empty(t, cookies)
}

func TestNewOAuthSecurityScheme_HasValidValue(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	result := ss.HasValidValue()

	assert.True(t, result)
}

func TestNewOAuthSecurityScheme_HasValidValueFalse_WhenValueIsNil(t *testing.T) {
	name := "token"
	ss := auth.NewOAuthSecurityScheme(name, nil, nil)

	result := ss.HasValidValue()

	assert.False(t, result)
}

func TestNewOAuthSecurityScheme_HasValidValueFalse_WhenValueIsEmptyString(t *testing.T) {
	name := "token"
	value := ""
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	result := ss.HasValidValue()

	assert.False(t, result)
}

func TestNewOAuthSecurityScheme_GetValidValueNil(t *testing.T) {
	name := "token"
	ss := auth.NewOAuthSecurityScheme(name, nil, nil)

	validValue := ss.GetValidValue()

	assert.Equal(t, nil, validValue)
}

func TestNewOAuthSecurityScheme_GetValidValue(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	validValue := ss.GetValidValue()

	assert.Equal(t, value, validValue)
}

func TestNewOAuthSecurityScheme_GetValidValueWriter(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)
	writer := ss.GetValidValueWriter()

	assert.Nil(t, writer)
}

func TestNewOAuthSecurityScheme_GetValidValueWriter_WithJWT(t *testing.T) {
	name := "token"
	value := jwt.FakeJWT

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)
	writer := ss.GetValidValueWriter()

	assert.IsType(t, &jwt.JWTWriter{}, writer)
}

func TestNewOAuthSecurityScheme_SetAttackValue(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	attackValue := "xyz789"
	ss.SetAttackValue(attackValue)

	assert.Equal(t, attackValue, ss.AttackValue)
}

func TestNewOAuthSecurityScheme_GetAttackValue(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewOAuthSecurityScheme(name, &value, nil)

	attackValue := "xyz789"
	ss.SetAttackValue(attackValue)

	result := ss.GetAttackValue()

	assert.Equal(t, attackValue, result)
}
