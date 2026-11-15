package issuernotvalidated_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	issuernotvalidated "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/issuer_not_validated"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validates := func(c jwtlib.MapClaims) bool { return c["iss"] == "https://idp/realms/a" }
	ignores := func(jwtlib.MapClaims) bool { return true }
	token := checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1", "iss": "https://idp/realms/a"})
	other := checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1", "iss": "https://idp/realms/b"})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"other token rejected", validates, token, checkbase.Options{OtherIssuerToken: other}, false, false},
		{"other token accepted", ignores, token, checkbase.Options{OtherIssuerToken: other}, true, false},
		{"re-signed token rejected", validates, token, checkbase.Options{HMACSecret: checkbasetest.Secret}, false, false},
		{"re-signed token accepted", ignores, token, checkbase.Options{HMACSecret: checkbasetest.Secret}, true, false},
		{"no other token nor secret", ignores, token, checkbase.Options{}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, issuernotvalidated.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
