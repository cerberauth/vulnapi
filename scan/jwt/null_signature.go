package jwt

import (
	"fmt"
	"strings"

	"github.com/cerberauth/vulnapi/internal/request"
)

func createNewJWTWithoutSignature(originalTokenString string) (string, error) {
	newTokenString, err := createNewJWTWithClaims(originalTokenString, []byte(""))
	if err != nil {
		return "", err
	}

	parts := strings.Split(newTokenString, ".")
	return strings.Join([]string{parts[0], parts[1], ""}, "."), nil
}

func NullSignatureScanHandler(url string, token string) []error {
	newToken, err := createNewJWTWithoutSignature(token)
	if err != nil {
		return []error{err}
	}

	statusCode, _, err := request.SendRequestWithBearerAuth(url, newToken)
	if err != nil {
		return []error{err}
	}

	if statusCode > 200 && statusCode <= 300 {
		return []error{fmt.Errorf("unexpected status code %d with a null signature", statusCode)}
	}

	return nil
}
