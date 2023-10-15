package jwt

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/request"
)

func BlankSecretScanHandler(url string, token string) []error {
	newToken, err := createNewJWTWithClaims(token, []byte(""))
	if err != nil {
		return []error{err}
	}

	statusCode, _, err := request.SendRequestWithBearerAuth(url, newToken)
	if err != nil {
		return []error{err}
	}

	if statusCode > 200 && statusCode <= 300 {
		return []error{fmt.Errorf("unexpected status code %d with a blank secret", statusCode)}
	}

	return nil
}

func DictSecretScanHandler(url string, token string) []error {
	// Use a dictionary attack to try finding the secret

	return nil
}
