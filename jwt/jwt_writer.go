package jwt

import (
	"errors"
	"time"

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
	// If the token has expired, we will extend it for 5 minutes so that it can pass the verification
	expirationTime, err := j.Token.Claims.GetExpirationTime()
	if err == nil && expirationTime != nil && expirationTime.Before(time.Now()) {
		claims := j.Token.Claims.(jwt.MapClaims)
		newClaims := jwt.MapClaims{}
		for k, v := range claims {
			newClaims[k] = v
		}
		newClaims["exp"] = time.Now().Add(5 * time.Minute).Unix()
		j.Token.Claims = newClaims
	}

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
