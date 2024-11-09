package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestSchemeName_String(t *testing.T) {
	scheme := auth.BasicScheme
	assert.Equal(t, "Basic", scheme.String())
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
