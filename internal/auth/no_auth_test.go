package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewNoAuthSecurityScheme(t *testing.T) {
	ss := auth.NewNoAuthSecurityScheme()
	assert.NotNil(t, ss)
}

func TestNoAuthSecurityScheme_GetScheme(t *testing.T) {
	ss := auth.NewNoAuthSecurityScheme()

	scheme := ss.GetScheme()

	assert.Equal(t, auth.NoneScheme, scheme)
}

func TestNoAuthSecurityScheme_GetType(t *testing.T) {
	ss := auth.NewNoAuthSecurityScheme()

	scheme := ss.GetType()

	assert.Equal(t, auth.None, scheme)
}

func TestNoAuthSecurityScheme_GetName(t *testing.T) {
	ss := auth.NewNoAuthSecurityScheme()

	scheme := ss.GetName()

	assert.Equal(t, "", scheme)
}

func TestNoAuthSecurityScheme_GetHeaders(t *testing.T) {
	ss := &auth.NoAuthSecurityScheme{}
	headers := ss.GetHeaders()
	assert.NotNil(t, headers)
	assert.Empty(t, headers)
}

func TestNoAuthSecurityScheme_GetCookies(t *testing.T) {
	ss := &auth.NoAuthSecurityScheme{}
	cookies := ss.GetCookies()
	assert.NotNil(t, cookies)
	assert.Empty(t, cookies)
}

func TestNoAuthSecurityScheme_GetValidValue(t *testing.T) {
	ss := &auth.NoAuthSecurityScheme{}
	validValue := ss.GetValidValue()
	assert.Equal(t, "", validValue)
}

func TestNoAuthSecurityScheme_GetValidValueWriter(t *testing.T) {
	ss := &auth.NoAuthSecurityScheme{}
	validValueWriter := ss.GetValidValueWriter()
	assert.Equal(t, "", validValueWriter)
}

func TestNoAuthSecurityScheme_SetAttackValue(t *testing.T) {
	ss := &auth.NoAuthSecurityScheme{}
	ss.SetAttackValue("attack value")
	// No assertion as this method does not return anything
}

func TestNoAuthSecurityScheme_GetAttackValue(t *testing.T) {
	ss := &auth.NoAuthSecurityScheme{}
	attackValue := ss.GetAttackValue()
	assert.Nil(t, attackValue)
}
