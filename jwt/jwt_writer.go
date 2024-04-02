package jwt

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type JWTWriter struct {
	Token *jwt.Token
}

func NewJWTWriter(token string) (*JWTWriter, error) {
	originalToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if originalToken == nil {
		return nil, errors.New("invalid JWT token")
	}

	return &JWTWriter{Token: originalToken}, nil
}

func (j *JWTWriter) SignWithMethodAndKey(method jwt.SigningMethod, key interface{}) (string, error) {
	newToken := jwt.NewWithClaims(method, j.Token.Claims)

	tokenString, err := newToken.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWTWriter) SignWithMethodAndRandomKey(method jwt.SigningMethod) (string, error) {
	key, err := generateKey(method)
	if err != nil {
		return "", err
	}
	return j.SignWithMethodAndKey(method, key)
}

func (j *JWTWriter) SignWithKey(key interface{}) (string, error) {
	return j.SignWithMethodAndKey(j.Token.Method, key)
}
