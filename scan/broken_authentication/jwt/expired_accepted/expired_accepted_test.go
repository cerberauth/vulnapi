package expiredaccepted_test

import (
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	expiredaccepted "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/expired_accepted"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	validates := func(c jwtlib.MapClaims) bool {
		exp, err := c.GetExpirationTime()
		return err == nil && exp != nil && exp.After(time.Now())
	}
	ignores := func(jwtlib.MapClaims) bool { return true }
	expired := checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1", "exp": time.Now().Add(-time.Hour).Unix()})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"expired rejected", validates, expired, checkbase.Options{}, false, false},
		{"expired accepted", ignores, expired, checkbase.Options{}, true, false},
		{"not expired", ignores, checkbasetest.Sign(t, jwtlib.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), checkbase.Options{}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, expiredaccepted.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
