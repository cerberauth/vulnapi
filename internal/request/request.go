package request

import (
	"context"
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
	Header  http.Header
	Cookies []*http.Cookie

	SecurityScheme *auth.SecurityScheme
}

func NewRequest(method string, url string, body io.Reader) (*Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	return &Request{req, http.Header{}, []*http.Cookie{}, nil}, nil
}

func (r *Request) WithHTTPHeaders(header http.Header) *Request {
	r.Header = header
	return r
}

func (r *Request) WithCookies(cookies []*http.Cookie) *Request {
	r.Cookies = cookies
	return r
}

func (r *Request) WithSecurityScheme(ss *auth.SecurityScheme) *Request {
	r.SecurityScheme = ss
	return r
}

func (r *Request) Do() (*http.Response, error) {
	r.Request.Header.Set("User-Agent", "vulnapi")

	for k, v := range r.Header {
		r.Request.Header.Set(k, v[0])
	}

	for _, c := range r.Cookies {
		r.Request.AddCookie(c)
	}

	if r.SecurityScheme != nil {
		securityScheme := *r.SecurityScheme
		for _, c := range securityScheme.GetCookies() {
			r.Request.AddCookie(c)
		}

		for k, v := range securityScheme.GetHeaders() {
			r.Request.Header.Set(k, v[0])
		}
	}

	return SharedClient.Do(r.Request)
}

func (r *Request) Clone(ctx context.Context) *Request {
	clone := *r
	clone.Request = r.Request.Clone(ctx)
	return &clone
}
