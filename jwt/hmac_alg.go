package jwt

import jwtlib "github.com/golang-jwt/jwt/v5"

func (j *JWTWriter) IsHMACAlg() bool {
	_, ok := j.Token.Method.(*jwtlib.SigningMethodHMAC)
	return ok
}
