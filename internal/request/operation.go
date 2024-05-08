package request

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
)

type Operations []*Operation

func (o Operations) Len() int      { return len(o) }
func (o Operations) Swap(i, j int) { o[i], o[j] = o[j], o[i] }
func (o Operations) Less(i, j int) bool {
	if o[i].Request.URL.String() == o[j].Request.URL.String() {
		return o[i].Method < o[j].Method
	}

	return o[i].Request.URL.String() < o[j].Request.URL.String()
}

type Operation struct {
	*Request

	SecuritySchemes []auth.SecurityScheme `json:"security_schemes"`
}

func NewOperation(method string, url string, header http.Header, cookies []*http.Cookie, securitySchemes []auth.SecurityScheme) (*Operation, error) {
	r, err := NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	r = r.WithHTTPHeaders(header).WithCookies(cookies)

	return NewOperationFromRequest(r, securitySchemes), nil
}

func NewOperationFromRequest(r *Request, securitySchemes []auth.SecurityScheme) *Operation {
	if len(securitySchemes) == 0 {
		securitySchemes = []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()}
	}

	return &Operation{
		Request: r,

		SecuritySchemes: securitySchemes,
	}
}

func (o *Operation) Clone() *Operation {
	o.Request = o.Request.Clone(o.Request.Context())

	var clonedSecuritySchemes []auth.SecurityScheme
	if o.SecuritySchemes != nil {
		clonedSecuritySchemes = make([]auth.SecurityScheme, len(o.SecuritySchemes))
		copy(clonedSecuritySchemes, o.SecuritySchemes)
	}

	return NewOperationFromRequest(o.Request, clonedSecuritySchemes)
}
