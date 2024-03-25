package jwt_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/jwt"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestIsHMACAlgWithHS256(t *testing.T) {
	token := jwtlib.New(jwtlib.SigningMethodHS256)
	tokenString, _ := token.SignedString([]byte(""))
	jwtWriter, err := jwt.NewJWTWriter(tokenString)

	assert.NoError(t, err)
	assert.True(t, jwtWriter.IsHMACAlg())
}

func TestIsHMACAlgWithRSA(t *testing.T) {
	privateKeyData := []byte(`
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKwkZA+Y19xPuGLCkk+JkrTnCo5bQvJcf0MdC73xg473
-----END PRIVATE KEY-----
`)

	key, _ := jwtlib.ParseEdPrivateKeyFromPEM(privateKeyData)
	token := jwtlib.New(jwtlib.SigningMethodEdDSA)
	tokenString, _ := token.SignedString(key)
	jwtWriter, err := jwt.NewJWTWriter(tokenString)

	assert.NoError(t, err)
	assert.False(t, jwtWriter.IsHMACAlg())
}
