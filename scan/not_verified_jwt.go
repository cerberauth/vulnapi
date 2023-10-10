package scan

import (
	"fmt"

	internalJwt "github.com/cerberauth/vulnapi/internal/jwt"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/golang-jwt/jwt/v5"
)

func NotVerifiedJwtScanHandler(url string, token string) []error {
	newToken, err := internalJwt.CreateNewJWTWithClaims(token, jwt.SigningMethodHS256, []byte(""))
	if err != nil {
		return []error{err}
	}

	statusCode, _, err := request.SendRequestWithBearerAuth(url, newToken)
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
