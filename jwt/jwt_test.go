package jwt_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/jwt"
)

func TestIsJWT(t *testing.T) {
	tests := []struct {
		token    string
		expected bool
	}{
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A", true},
		{"invalid.jwt.token", false},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.", true},
		{"", false},
	}

	for _, test := range tests {
		result := jwt.IsJWT(test.token)
		if result != test.expected {
			t.Errorf("IsJWT(%q) = %v; want %v", test.token, result, test.expected)
		}
	}
}
