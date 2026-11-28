package checkbasetest_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase/checkbasetest"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbesSendOperationMethodAndBody(t *testing.T) {
	url, requests := checkbasetest.Server(t, func(jwtlib.MapClaims) bool { return true })
	op := checkbasetest.Operation(t, url, checkbasetest.Sign(t, jwtlib.MapClaims{"sub": "1"}))

	_, reason := checkbasetest.Run(t, checkbase.ProbeCtxCheck, op, checkbase.Options{})

	assert.Empty(t, reason)
	require.NotEmpty(t, *requests)
	for _, r := range *requests {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, `{"name":"test"}`, r.Body)
	}
}
