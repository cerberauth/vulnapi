package request

import (
	"io"
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
)

type Request struct {
	*Client
	*http.Request
}

func NewRequest(method string, reqUrl string, body io.Reader, client *Client) (*Request, error) {
	if client == nil {
		client = GetDefaultClient()
	}

	req, err := http.NewRequest(method, reqUrl, body)
	if err != nil {
		return nil, err
	}

	for k, v := range client.Header {
		req.Header.Set(k, v[0])
	}

	for _, c := range client.Cookies {
		req.AddCookie(c)
	}

	return &Request{client, req}, nil
}

func (r *Request) WithHeader(header http.Header) *Request {
	for k, v := range header {
		r.Request.Header.Set(k, v[0])
	}
	return r
}

func (r *Request) WithCookies(cookies []*http.Cookie) *Request {
	for _, c := range cookies {
		r.Request.AddCookie(c)
	}
	return r
}

func (r *Request) WithSecurityScheme(securityScheme auth.SecurityScheme) *Request {
	if securityScheme.GetCookies() != nil {
		r.WithCookies(securityScheme.GetCookies())
	}

	if securityScheme.GetHeaders() != nil {
		r.WithHeader(securityScheme.GetHeaders())
	}

	return r
}

func (r *Request) Do() (*http.Response, error) {
	r.Request.Header.Set("User-Agent", "vulnapi")

	rl.Take()
	res, err := r.Client.Do(r.Request)
	return res, err
}
