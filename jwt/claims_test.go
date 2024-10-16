package jwt_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/jwt"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestOrderedMapClaims_MarshalJSON(t *testing.T) {
	token := libjwt.NewWithClaims(libjwt.SigningMethodHS256, libjwt.MapClaims{
		"foo": "bar",
		"baz": 123,
	})
	tokenString, err := token.SignedString([]byte("secret"))
	assert.NoError(t, err)

	claims := jwt.NewOrderedMapClaims(token)
	claims.Raw = tokenString

	jsonBytes, err := claims.MarshalJSON()
	assert.NoError(t, err)

	assert.JSONEq(t, `{"foo":"bar","baz":123}`, string(jsonBytes))
}

func TestOrderedMapClaims_MarshalJSON_EmptyToken(t *testing.T) {
	claims := jwt.OrderedMapClaims{}

	_, err := claims.MarshalJSON()
	assert.Error(t, err)
	assert.Equal(t, libjwt.ErrTokenMalformed, err)
}

func TestOrderedMapClaims_MarshalJSON_MalformedToken(t *testing.T) {
	claims := jwt.OrderedMapClaims{Raw: "malformed.token.string"}

	_, err := claims.MarshalJSON()
	assert.Error(t, err)
	assert.Equal(t, libjwt.ErrTokenMalformed, err)
}
