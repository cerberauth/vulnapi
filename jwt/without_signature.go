package jwt

import "strings"

func (j *JWTWriter) WithoutSignature() (string, error) {
	newTokenString, err := j.SignWithMethodAndKey(j.GetToken().Method, []byte(""))
	if err != nil {
		return "", err
	}

	parts := strings.Split(newTokenString, ".")
	return strings.Join([]string{parts[0], parts[1], ""}, "."), nil
}
