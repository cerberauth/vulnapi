package scopenotvalidated_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	scopenotvalidated "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/scope_not_validated"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validates := func(c jwtlib.MapClaims) bool { return c["scope"] == "write" }
	ignores := func(jwtlib.MapClaims) bool { return true }
	token := checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1", "scope": "write"})
	secret := checkbase.Options{HMACSecret: checkbasetest.Secret}

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"scope validated", validates, token, secret, false, false},
		{"scope ignored", ignores, token, secret, true, false},
		{"no scope claim", ignores, checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1"}), secret, false, true},
		{"secret unknown", ignores, token, checkbase.Options{}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, scopenotvalidated.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
