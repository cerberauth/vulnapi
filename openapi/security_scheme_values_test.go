package openapi_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/openapi"
	"github.com/stretchr/testify/assert"
)

func TestNewSecuritySchemeValues(t *testing.T) {
	values := map[string]interface{}{
		"key": "value",
	}
	securitySchemeValues := openapi.NewSecuritySchemeValues(values)

	assert.Nil(t, securitySchemeValues.Default)
	assert.NotNil(t, securitySchemeValues.Values)
	assert.Equal(t, values, securitySchemeValues.Values)
}

func TestNewEmptySecuritySchemeValues(t *testing.T) {
	securitySchemeValues := openapi.NewEmptySecuritySchemeValues()

	assert.Nil(t, securitySchemeValues.Default)
	assert.NotNil(t, securitySchemeValues.Values)
	assert.Empty(t, securitySchemeValues.Values)
}

func TestSecuritySchemeValues_WithDefault(t *testing.T) {
	securitySchemeValues := openapi.NewEmptySecuritySchemeValues()
	securitySchemeValues.WithDefault("default")

	assert.Equal(t, "default", securitySchemeValues.Default)
}

func TestSecuritySchemeValues_GetDefault(t *testing.T) {
	securitySchemeValues := openapi.NewEmptySecuritySchemeValues()
	securitySchemeValues.WithDefault("default")

	assert.Equal(t, "default", securitySchemeValues.GetDefault())
}

func TestSecuritySchemeValues_Get(t *testing.T) {
	securitySchemeValues := openapi.NewEmptySecuritySchemeValues()
	securitySchemeValues.WithDefault("default")
	securitySchemeValues.Set("key", "value")

	assert.Equal(t, "value", securitySchemeValues.Get("key"))
}

func TestSecuritySchemeValues_Get_WhenNotExist(t *testing.T) {
	securitySchemeValues := openapi.NewEmptySecuritySchemeValues()
	securitySchemeValues.WithDefault("default")

	assert.Equal(t, "default", securitySchemeValues.Get("key"))
}

func TestSecuritySchemeValues_Set(t *testing.T) {
	securitySchemeValues := openapi.NewEmptySecuritySchemeValues()
	securitySchemeValues.Set("key", "value")

	assert.Equal(t, "value", securitySchemeValues.Get("key"))
}
