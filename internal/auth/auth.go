package auth

import "net/http"

type Type string
type Scheme string
type SchemeIn string

const (
	HttpType      Type = "http"
	OAuth2        Type = "oauth2"
	OpenIdConnect Type = "openIdConnect"
	ApiKey        Type = "apiKey"
)

const (
	BasicScheme  Scheme = "basic"
	BearerScheme Scheme = "bearer"
	NoneScheme   Scheme = "none"
)

const (
	InHeader  SchemeIn = "header"
	InCookie  SchemeIn = "cookie"
	InUnknown SchemeIn = "unknown"
)

type SecurityScheme interface {
	GetHeaders() http.Header
	GetCookies() []*http.Cookie
	GetValidValue() interface{}
	SetAttackValue(v interface{})
	GetAttackValue() interface{}
}
