package scan

import (
	"fmt"

	internalJwt "github.com/cerberauth/vulnapi/internal/jwt"
	"github.com/cerberauth/vulnapi/internal/request"
)

func BlankJwtSecretScanHandler(url string, token string) []error {
	newToken, err := internalJwt.CreateNewJWTWithClaims(token, []byte(""))
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

func DictJwtSecretScanHandler(url string, token string) []error {
	// Use a dictionary attack to try finding the secret

	return nil
}

func (s *Scan) WithWeakJwtSecretScan() *Scan {
	return s.AddPendingScanHandler(BlankJwtSecretScanHandler).AddPendingScanHandler(DictJwtSecretScanHandler)
}
