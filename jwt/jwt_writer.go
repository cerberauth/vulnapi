package jwt

import "github.com/golang-jwt/jwt/v5"

type JWTWriter struct {
	Token *jwt.Token
}

func NewJWTWriter(token string) (*JWTWriter, error) {
	// Parse the original JWT token
	originalToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	return &JWTWriter{Token: originalToken}, nil
}

func (j *JWTWriter) SignWithMethodAndKey(method jwt.SigningMethod, key interface{}) (string, error) {
	// Create a new token with the new claims
	newToken := jwt.NewWithClaims(method, j.Token.Claims)

	// Sign the new token with the new secret key
	tokenString, err := newToken.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWTWriter) SignWithKey(key interface{}) (string, error) {
	return j.SignWithMethodAndKey(j.Token.Method, key)
}
