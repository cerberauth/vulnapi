package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/golang-jwt/jwt/v5"
)

func createNewJWTWithClaims(originalTokenString string, method jwt.SigningMethod, newSecretKey string) (string, error) {
	// Parse the original JWT token
	originalToken, _, err := new(jwt.Parser).ParseUnverified(originalTokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}

	// Create a new token with the new claims
	newToken := jwt.NewWithClaims(method, originalToken.Claims)

	// Sign the new token with the new secret key
	tokenString, err := newToken.SignedString([]byte(newSecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func NotVerifiedJwtScanHandler(url string, token string) []error {
	newToken, err := createNewJWTWithClaims(token, jwt.SigningMethodHS256, "")
	if err != nil {
		return []error{err}
	}

	statusCode, err := request.SendRequestWithBearerAuth(url, newToken)
	if err != nil {
		return []error{err}
	}

	if statusCode > 200 && statusCode <= 300 {
		return []error{fmt.Errorf("unexpected status code %d with an invalid forged token", statusCode)}
	}

	return nil
}

func (s *Scan) WithNotVerifiedJwtScan() *Scan {
	return s.AddPendingScanHandler(NotVerifiedJwtScanHandler)
}
