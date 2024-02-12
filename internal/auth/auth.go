package auth

import "net/http"

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

type Operations []Operation

func (o Operations) Len() int      { return len(o) }
func (o Operations) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Operations) Less(i, j int) bool {
	if o[i].Url == o[j].Url {
		return o[i].Method < o[j].Method
	}

	return o[i].Url < o[j].Url
}

type Operation struct {
	Url     string
	Method  string
	Headers *http.Header
	Cookies []http.Cookie

	SecuritySchemes []SecurityScheme
}
