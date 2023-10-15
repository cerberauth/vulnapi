package jwt

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/golang-jwt/jwt/v5"
)

func AlgNoneJwtScanHandler(url string, token string) []error {
	newToken, err := createNewJWTWithClaimsAndMethod(token, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		return []error{err}
	}

	statusCode, _, err := request.SendRequestWithBearerAuth(url, newToken)
	if err != nil {
		return []error{err}
	}

	if statusCode > 200 && statusCode <= 300 {
		return []error{fmt.Errorf("unexpected status code %d with an alg none forged token", statusCode)}
	}

	return nil
}
