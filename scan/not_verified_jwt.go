package scan

import (
	"fmt"

	internalJwt "github.com/cerberauth/vulnapi/internal/jwt"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/golang-jwt/jwt/v5"
)

func NotVerifiedJwtScanHandler(url string, token string) []error {
	newTokenA, err := internalJwt.CreateNewJWTWithClaimsAndMethod(token, jwt.SigningMethodHS256, []byte("a"))
	if err != nil {
		return []error{err}
	}

	newTokenB, err := internalJwt.CreateNewJWTWithClaimsAndMethod(token, jwt.SigningMethodHS256, []byte("b"))
	if err != nil {
		return []error{err}
	}

	statusCodeA, _, errRequestA := request.SendRequestWithBearerAuth(url, newTokenA)
	statusCodeB, _, errRequestB := request.SendRequestWithBearerAuth(url, newTokenB)

	var errors []error
	if errRequestA != nil {
		errors = append(errors, errRequestA)
	}

	if errRequestB != nil {
		errors = append(errors, errRequestB)
	}

	if statusCodeA > 200 && statusCodeA <= 300 {
		errors = append(errors, fmt.Errorf("unexpected status code %d with an invalid forged token", statusCodeA))
	}

	if statusCodeA != statusCodeB {
		errors = append(errors, fmt.Errorf("status code are not the same between the two attempts"))
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

func (s *Scan) WithNotVerifiedJwtScan() *Scan {
	return s.AddPendingScanHandler(NotVerifiedJwtScanHandler)
}
