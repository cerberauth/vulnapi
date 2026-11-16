package claimremoval_test

import (
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	claimremoval "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/claim_removal"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func requires(names ...string) func(jwtlib.MapClaims) bool {
	return func(c jwtlib.MapClaims) bool {
		for _, name := range names {
			if _, ok := c[name]; !ok {
				return false
			}
		}
		return true
	}
}

func TestCheck(t *testing.T) {
	now := time.Now()
	token := checkbasetest.Sign(t, jwtlib.MapClaims{"iss": "idp", "aud": "api", "sub": "1", "exp": now.Add(time.Hour).Unix(), "nbf": now.Unix(), "iat": now.Unix()})
	secret := checkbase.Options{HMACSecret: checkbasetest.Secret}

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"every claim required", requires("iss", "aud", "sub", "exp", "nbf", "iat"), token, secret, false, false},
		{"aud not required", requires("iss", "sub", "exp", "nbf", "iat"), token, secret, true, false},
		{"no claim required", requires(), token, secret, true, false},
		{"secret unknown", requires(), token, checkbase.Options{}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, claimremoval.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
