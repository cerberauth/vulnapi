package request

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
)

type Operations []*Operation

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

	SecuritySchemes []auth.SecurityScheme
}

func NewOperation(url, method string, headers *http.Header, cookies []http.Cookie, securitySchemes []auth.SecurityScheme) *Operation {
	if len(securitySchemes) == 0 {
		securitySchemes = []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	}

	operation := Operation{
		Url:             url,
		Method:          method,
		Headers:         headers,
		Cookies:         cookies,
		SecuritySchemes: securitySchemes,
	}

	return &operation
}

func (o *Operation) Clone() *Operation {
	clonedHeaders := make(http.Header)
	if o.Headers != nil {
		clonedHeaders = o.Headers.Clone()
	}

	clonedCookies := make([]http.Cookie, len(o.Cookies))
	copy(clonedCookies, o.Cookies)

	clonedSecuritySchemes := make([]auth.SecurityScheme, len(o.SecuritySchemes))
	copy(clonedSecuritySchemes, o.SecuritySchemes)

	return NewOperation(o.Url, o.Method, &clonedHeaders, clonedCookies, clonedSecuritySchemes)
}
