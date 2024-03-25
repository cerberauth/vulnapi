package request

import (
	"io"
	"net/http"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
)

var SharedClient = &http.Client{
	Timeout: time.Second * 10,
}

type Request struct {
	*http.Request
	SecurityScheme *auth.SecurityScheme
}

func NewRequest(method string, url string, body io.Reader) (*Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	return &Request{req, nil}, nil
}

func (r *Request) WithSecurityScheme(ss *auth.SecurityScheme) *Request {
	r.SecurityScheme = ss
	return r
}

func (r *Request) Do() (*http.Response, error) {
	r.Header.Set("User-Agent", "vulnapi")

	if securityScheme := *r.SecurityScheme; securityScheme != nil {
		for _, c := range securityScheme.GetCookies() {
			r.AddCookie(c)
		}

		for n, h := range securityScheme.GetHeaders() {
			r.Header.Add(n, h[0])
		}
	}

	return SharedClient.Do(r.Request)
}
