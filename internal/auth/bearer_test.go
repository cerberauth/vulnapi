package auth_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthorizationBearerSecurityScheme(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	assert.Equal(t, auth.HttpType, ss.Type)
	assert.Equal(t, auth.BearerScheme, ss.Scheme)
	assert.Equal(t, auth.InHeader, ss.In)
	assert.Equal(t, name, ss.Name)
	assert.Equal(t, &value, ss.ValidValue)
	assert.Equal(t, "", ss.AttackValue)
}

func TestBearerSecurityScheme_GetHeaders(t *testing.T) {
	name := "token"
	value := "abc123"
	attackValue := "xyz789"

	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)
	ss.SetAttackValue(attackValue)

	headers := ss.GetHeaders()

	assert.Equal(t, http.Header{
		"Authorization": []string{"Bearer xyz789"},
	}, headers)
}

func TestBearerSecurityScheme_GetCookies(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	cookies := ss.GetCookies()

	assert.Empty(t, cookies)
}

func TestBearerSecurityScheme_GetValidValue(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	validValue := ss.GetValidValue()

	assert.Equal(t, value, validValue)
}

func TestBearerSecurityScheme_GetValidValueWriter(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)
	writer := ss.GetValidValueWriter()

	assert.Equal(t, nil, writer)
}

func TestBearerSecurityScheme_SetAttackValue(t *testing.T) {
	name := "token"
	value := "abc123"

	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	attackValue := "xyz789"
	ss.SetAttackValue(attackValue)

	assert.Equal(t, attackValue, ss.AttackValue)
}

func TestBearerSecurityScheme_GetAttackValue(t *testing.T) {
	name := "token"
	value := "abc123"
	ss := auth.NewAuthorizationBearerSecurityScheme(name, &value)

	attackValue := "xyz789"
	ss.SetAttackValue(attackValue)

	result := ss.GetAttackValue()

	assert.Equal(t, attackValue, result)
}
