package jwt

import (
	"errors"
	"regexp"

	"github.com/golang-jwt/jwt/v5"
)

var jwtRegexp = `^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`

func IsJWT(token string) bool {
	matched, err := regexp.MatchString(jwtRegexp, token)
	if err != nil || !matched {
		return false
	}

	_, _, err = new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	return err == nil && !errors.Is(err, jwt.ErrTokenUnverifiable) && !errors.Is(err, jwt.ErrTokenSignatureInvalid)
}
