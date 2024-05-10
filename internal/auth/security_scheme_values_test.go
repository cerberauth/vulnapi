package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewSecuritySchemeValues(t *testing.T) {
	values := auth.NewSecuritySchemeValues()

	assert.Nil(t, values.Default)
	assert.NotNil(t, values.Values)
	assert.Empty(t, values.Values)
}

func TestNewSecuritySchemeValuesWithDefault(t *testing.T) {
	defaultValue := "default"
	values := auth.NewSecuritySchemeValuesWithDefault(&defaultValue)

	assert.Equal(t, &defaultValue, values.Default)
	assert.NotNil(t, values.Values)
	assert.Empty(t, values.Values)
}
