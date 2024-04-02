package jwt_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/jwt"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsHS256(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodHS256)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsRS256(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodRS256)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsRS384(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodRS384)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsRS512(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodRS512)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsES256(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodES256)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsES384(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodES384)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTWriter_SignWithMethodAndRandomKey_WhenSigningMethodIsES512(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	writer, _ := jwt.NewJWTWriter(token)

	token, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodES512)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}
