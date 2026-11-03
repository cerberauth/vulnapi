package seclist_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/seclist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecListFromEmbeddedFile(t *testing.T) {
	seclist, err := seclist.NewSecListFromEmbeddedFile("seclist", "graphql.txt")

	require.NoError(t, err)
	assert.Equal(t, "seclist", seclist.Name)
	assert.Equal(t, "___graphql", seclist.Items[0])
	assert.Equal(t, "altair", seclist.Items[1])
	assert.Equal(t, "explorer", seclist.Items[2])
	assert.NotContains(t, seclist.Items, "")
}

func TestNewSecListFromEmbeddedFileWhenUnknown(t *testing.T) {
	_, err := seclist.NewSecListFromEmbeddedFile("seclist", "unknown.txt")

	assert.ErrorContains(t, err, `unknown sec list "unknown.txt"`)
}
