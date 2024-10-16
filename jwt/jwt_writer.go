package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTWriter struct {
	token *jwt.Token
}

func NewJWTWriter(token string) (*JWTWriter, error) {
	tokenParsed, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if tokenParsed == nil {
		return nil, errors.New("invalid JWT token")
	}

	return &JWTWriter{token: tokenParsed}, nil
}

func NewJWTWriterWithValidClaims(j *JWTWriter) *JWTWriter {
	newJwtWriter := j.Clone()
	token := newJwtWriter.GetToken()

	claims := token.Claims.(jwt.MapClaims)

	// If the token has expired, we will extend it for 5 minutes so that it can pass the verification
	expirationTime, err := claims.GetExpirationTime()
	if err == nil && expirationTime != nil && expirationTime.Before(time.Now()) {
		newJwtWriter.token.Claims.(jwt.MapClaims)["exp"] = time.Now().Add(5 * time.Minute).Unix()
	}

	// If the token is not valid yet, we will set the nbf claim to the current time
	notBeforeTime, err := claims.GetNotBefore()
	if err == nil && notBeforeTime != nil && notBeforeTime.After(time.Now()) {
		newJwtWriter.token.Claims.(jwt.MapClaims)["nbf"] = time.Now().Unix()
	}

	return newJwtWriter
}

func (j *JWTWriter) GetToken() *jwt.Token {
	return j.token
}

func (j *JWTWriter) SignWithMethodAndKey(method jwt.SigningMethod, key interface{}) (string, error) {
	token := jwt.NewWithClaims(method, NewOrderedMapClaims(j.token))

	tokenString, err := token.SignedString(key)
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
	return j.SignWithMethodAndKey(j.token.Method, key)
}

func (j *JWTWriter) Clone() *JWTWriter {
	w, err := NewJWTWriter(j.GetToken().Raw)
	if err != nil {
		panic(err)
	}

	return w
}
