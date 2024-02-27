package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestSchemeName_String(t *testing.T) {
	scheme := auth.BasicScheme
	assert.Equal(t, "basic", scheme.String())
}

func TestSchemeName_Set_Valid(t *testing.T) {
	scheme := auth.SchemeName("")
	err := scheme.Set("bearer")
	assert.NoError(t, err)
	assert.Equal(t, auth.BearerScheme, scheme)
}

func TestSchemeName_Set_Invalid(t *testing.T) {
	scheme := auth.SchemeName("")
	err := scheme.Set("invalid")
	assert.Error(t, err)
	assert.EqualError(t, err, `must be one of "basic", "bearer", "digest", "oauth", "privateToken"`)
	assert.Equal(t, auth.SchemeName(""), scheme)
}

func TestSchemeName_Type(t *testing.T) {
	scheme := auth.BasicScheme
	assert.Equal(t, "scheme", scheme.Type())
}

func TestSchemeIn(t *testing.T) {
	schemeIn := auth.InHeader
	assert.Equal(t, "header", string(schemeIn))
}

func TestSchemeIn_String(t *testing.T) {
	schemeIn := auth.InHeader
	assert.Equal(t, "header", string(schemeIn))
}
