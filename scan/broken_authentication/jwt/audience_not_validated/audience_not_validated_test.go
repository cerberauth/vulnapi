package audiencenotvalidated_test

import (
	"testing"

	audiencenotvalidated "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/audience_not_validated"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validates := func(c jwtlib.MapClaims) bool { return c["aud"] == "api" }
	ignores := func(jwtlib.MapClaims) bool { return true }
	token := checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1", "aud": "api"})
	other := checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1", "aud": "billing"})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"other token rejected", validates, token, checkbase.Options{OtherAudienceToken: other}, false, false},
		{"other token accepted", ignores, token, checkbase.Options{OtherAudienceToken: other}, true, false},
		{"re-signed token rejected", validates, token, checkbase.Options{HMACSecret: checkbasetest.Secret}, false, false},
		{"re-signed token accepted", ignores, token, checkbase.Options{HMACSecret: checkbasetest.Secret}, true, false},
		{"no other token nor secret", ignores, token, checkbase.Options{}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, audiencenotvalidated.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
