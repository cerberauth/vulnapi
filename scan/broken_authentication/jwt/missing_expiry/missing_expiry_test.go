package missingexpiry_test

import (
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	missingexpiry "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/missing_expiry"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestCheck(t *testing.T) {
	ignores := func(jwtlib.MapClaims) bool { return true }

	testCases := []struct {
		name       string
		accept     func(jwtlib.MapClaims) bool
		token      string
		options    checkbase.Options
		vulnerable bool
		skipped    bool
	}{
		{"with exp", ignores, checkbasetest.Sign(t, jwtlib.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}), checkbase.Options{}, false, false},
		{"without exp", ignores, checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1"}), checkbase.Options{}, true, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url, _ := checkbasetest.Server(t, tc.accept)

			f, reason := checkbasetest.Run(t, missingexpiry.Check, checkbasetest.Operation(t, url, tc.token), tc.options)

			assert.Equal(t, tc.skipped, reason != "", reason)
			assert.Equal(t, tc.vulnerable, f != nil)
		})
	}
}
