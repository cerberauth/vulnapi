package jwt_test

import (
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/jwt"
	libjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestJWTWriter_SignWithMethodAndRandomKey_SigningMethodIsHS256(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tokenParsed, _, _ := new(libjwt.Parser).ParseUnverified(token, libjwt.MapClaims{})
	writer, _ := jwt.NewJWTWriter(token)

	newToken, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodHS256)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEqual(t, token, newToken)

	newTokenParsed, _, err := new(libjwt.Parser).ParseUnverified(newToken, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodHS256, newTokenParsed.Method)
	assert.Equal(t, tokenParsed.Claims, newTokenParsed.Claims)
}

func TestJWTWriter_SignWithMethodAndRandomKey_SigningMethodIsHS512(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tokenParsed, _, _ := new(libjwt.Parser).ParseUnverified(token, libjwt.MapClaims{})
	writer, _ := jwt.NewJWTWriter(token)

	newToken, err := writer.SignWithMethodAndRandomKey(libjwt.SigningMethodHS512)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEqual(t, token, newToken)

	newTokenParsed, _, err := new(libjwt.Parser).ParseUnverified(newToken, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodHS512, newTokenParsed.Method)
	assert.Equal(t, tokenParsed.Claims, newTokenParsed.Claims)
}

func TestJWTWriter_MakeClaimsValid_WhenTokenExpired(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.4Adcj3UFYzPUVaVF43FmMab6RlaQD8A9V8wFzzht-KQ"
	tokenParsed, _, _ := new(libjwt.Parser).ParseUnverified(token, libjwt.MapClaims{})
	writer, _ := jwt.NewJWTWriter(token)

	newToken, err := jwt.NewJWTWriterWithValidClaims(writer).SignWithMethodAndRandomKey(libjwt.SigningMethodHS256)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEqual(t, token, newToken)

	newTokenParsed, _, err := new(libjwt.Parser).ParseUnverified(newToken, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodHS256, newTokenParsed.Method)

	subject, _ := tokenParsed.Claims.GetSubject()
	newSubject, _ := newTokenParsed.Claims.GetSubject()
	assert.Equal(t, subject, newSubject)

	newExpirationTime, _ := newTokenParsed.Claims.GetExpirationTime()
	assert.True(t, newExpirationTime.After(time.Now()))
}

func TestJWTWriter_MakeClaimsValid_WhenTokenNotBefore(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJuYmYiOjIwMTYyMzkwMjJ9.ymnE0GznV0dMkjANTQl8IqBSlTi9RFWfBeT42jBNrU4"
	tokenParsed, _, _ := new(libjwt.Parser).ParseUnverified(token, libjwt.MapClaims{})
	writer, _ := jwt.NewJWTWriter(token)

	newToken, err := jwt.NewJWTWriterWithValidClaims(writer).SignWithMethodAndRandomKey(libjwt.SigningMethodHS256)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.NotEqual(t, token, newToken)

	newTokenParsed, _, err := new(libjwt.Parser).ParseUnverified(newToken, libjwt.MapClaims{})
	assert.NoError(t, err)
	assert.Equal(t, libjwt.SigningMethodHS256, newTokenParsed.Method)

	subject, _ := tokenParsed.Claims.GetSubject()
	newSubject, _ := newTokenParsed.Claims.GetSubject()
	assert.Equal(t, subject, newSubject)

	newNotBeforeTime, _ := newTokenParsed.Claims.GetNotBefore()
	assert.True(t, newNotBeforeTime.Before(time.Now()))
}

func TestJWTWriter_SignWithMethodAndKey_KeepClaimsOrder(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJuYmYiOjIwMTYyMzkwMjJ9.ymnE0GznV0dMkjANTQl8IqBSlTi9RFWfBeT42jBNrU4"
	expectedToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJuYmYiOjIwMTYyMzkwMjJ9.jmuDobK90TLrK9oUUjjE9OEXcCKH9ZOCO11-ZRewa5k"
	writer, _ := jwt.NewJWTWriter(token)

	newToken, err := writer.SignWithMethodAndKey(libjwt.SigningMethodHS256, []byte("newSecret"))
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, expectedToken, newToken)
}
