package jwt

import jwtlib "github.com/golang-jwt/jwt/v5"

func (j *JWTWriter) WithAlgNone() (string, error) {
	return j.SignWithMethodAndKey(jwtlib.SigningMethodNone, jwtlib.UnsafeAllowNoneSignatureType)
}
