package auth

import (
	"net/http"
)

type Type string

const (
	HttpType      Type = "http"
	OAuth2        Type = "oauth2"
	OpenIdConnect Type = "openIdConnect"
	ApiKey        Type = "apiKey"
)

type SecurityScheme interface {
	GetHeaders() http.Header
	GetCookies() []*http.Cookie
	GetValidValue() interface{}
	SetAttackValue(v interface{})
	GetAttackValue() interface{}
}

type NoAuthSecurityScheme struct{}

var _ SecurityScheme = (*NoAuthSecurityScheme)(nil)

func NewNoAuthSecurityScheme() *NoAuthSecurityScheme {
	return &NoAuthSecurityScheme{}
}

func (ss *NoAuthSecurityScheme) GetHeaders() http.Header {
	return http.Header{}
}

func (ss *NoAuthSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *NoAuthSecurityScheme) GetValidValue() interface{} {
	return ""
}

func (ss *NoAuthSecurityScheme) SetAttackValue(v interface{}) {}

func (ss *NoAuthSecurityScheme) GetAttackValue() interface{} {
	return nil
}
