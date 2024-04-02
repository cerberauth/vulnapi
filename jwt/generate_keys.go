package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

func generateKey(method jwt.SigningMethod) (interface{}, error) {
	switch method.Alg() {
	case jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodPS384.Alg(),
		jwt.SigningMethodPS512.Alg():
		privateKeyRS, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return "", err
		}
		return privateKeyRS, nil

	case jwt.SigningMethodES256.Alg():
		privateKeyES256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		return privateKeyES256, nil

	case jwt.SigningMethodES384.Alg():
		privateKeyES384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return "", err
		}
		return privateKeyES384, nil

	case jwt.SigningMethodES512.Alg():
		privateKeyES512, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return "", err
		}
		return privateKeyES512, nil

	case jwt.SigningMethodHS256.Alg(),
		jwt.SigningMethodHS384.Alg(),
		jwt.SigningMethodHS512.Alg():
		keyHS := make([]byte, 64)
		_, err := rand.Read(keyHS)
		if err != nil {
			return "", err
		}
		return keyHS, nil

	case jwt.SigningMethodNone.Alg():
		return nil, nil
	}

	return "", errors.New("unsupported signing method")
}
