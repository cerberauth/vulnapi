package jwt

import "github.com/golang-jwt/jwt/v5"

func createNewJWTWithClaimsAndMethod(originalTokenString string, method jwt.SigningMethod, newSecretKey interface{}) (string, error) {
	// Parse the original JWT token
	originalToken, _, err := new(jwt.Parser).ParseUnverified(originalTokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	// Create a new token with the new claims
	newToken := jwt.NewWithClaims(method, originalToken.Claims)

	// Sign the new token with the new secret key
	tokenString, err := newToken.SignedString(newSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func createNewJWTWithClaims(originalTokenString string, newSecretKey interface{}) (string, error) {
	// Parse the original JWT token
	originalToken, _, err := new(jwt.Parser).ParseUnverified(originalTokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	// Create a new token with the new claims and method
	newToken := jwt.NewWithClaims(originalToken.Method, originalToken.Claims)

	// Sign the new token with the new secret key
	tokenString, err := newToken.SignedString(newSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
