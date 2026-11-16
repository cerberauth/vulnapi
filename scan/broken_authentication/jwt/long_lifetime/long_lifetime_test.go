package longlifetime_test

import (
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	longlifetime "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/long_lifetime"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	ignores := func(jwtlib.MapClaims) bool { return true }
	now := time.Now()
	day := checkbasetest.Sign(t, jwtlib.MapClaims{"iat": now.Unix(), "exp": now.Add(2 * time.Hour).Unix()})

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"below default", ignores, day, checkbase.Options{}, false, false},
		{"above configured", ignores, day, checkbase.Options{MaxTokenLifetime: time.Hour}, true, false},
		{"above default", ignores, checkbasetest.Sign(t, jwtlib.MapClaims{"iat": now.Unix(), "exp": now.Add(30 * 24 * time.Hour).Unix()}), checkbase.Options{}, true, false},
		{"without exp", ignores, checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1"}), checkbase.Options{}, false, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, longlifetime.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
