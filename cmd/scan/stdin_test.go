package scan

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadToken(t *testing.T) {
	token, err := readToken(strings.NewReader("  token\n"))

	require.NoError(t, err)
	assert.Equal(t, "token", *token)
}

func TestReadTokenWhenEmpty(t *testing.T) {
	token, err := readToken(strings.NewReader(" \n"))

	assert.Nil(t, token)
	assert.EqualError(t, err, "no token found on stdin")
}
