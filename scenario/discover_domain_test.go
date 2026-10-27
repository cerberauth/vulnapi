package scenario

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsInScope(t *testing.T) {
	assert.True(t, isInScope("example.com", "example.com"))
	assert.True(t, isInScope("api.example.com", "example.com"))
	assert.True(t, isInScope("API.Example.com.", "example.com"))
	assert.False(t, isInScope("example.com.evil.net", "example.com"))
	assert.False(t, isInScope("notexample.com", "example.com"))
	assert.False(t, isInScope("server-1-2-3-4.cloudprovider.net", "example.com"))
}

func TestFilterFQDNs(t *testing.T) {
	fqdns := []string{
		"example.com",
		"api.example.com",
		"ec2-1-2-3-4.compute.amazonaws.com",
		"API.example.com.",
		"www.example.com",
		"cdn.provider.net",
	}

	assert.Equal(t, []string{"example.com", "api.example.com", "www.example.com"}, filterFQDNs(fqdns, "example.com"))
}
