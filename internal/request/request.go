package request

import (
	"bytes"
	"io"
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
)

type Request struct {
	Body        []byte
	Client      *Client
	HttpRequest *http.Request
}

func getBody(body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, nil
	}

	if bodyBuffer, ok := body.(*bytes.Buffer); ok {
		if bodyBuffer == nil {
			return nil, nil
		}
		return bodyBuffer.Bytes(), nil
	}

	return io.ReadAll(body)
}

func NewRequest(method string, url string, body io.Reader, client *Client) (*Request, error) {
	if client == nil {
		client = GetDefaultClient()
	}

	var bodyBuffer, err = getBody(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(bodyBuffer))
	if err != nil {
		return nil, err
	}

	for k, v := range client.Header {
		req.Header.Set(k, v[0])
	}

	for _, c := range client.Cookies {
		req.AddCookie(c)
	}

	return &Request{
		Body: bodyBuffer,

		Client:      client,
		HttpRequest: req,
	}, nil
}

func (r *Request) WithHeader(header http.Header) *Request {
	for k, v := range header {
		r.SetHeader(k, v[0])
	}
	return r
}

func (r *Request) WithCookies(cookies []*http.Cookie) *Request {
	for _, c := range cookies {
		r.AddCookie(c)
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

func (r *Request) GetMethod() string {
	return r.HttpRequest.Method
}

func (r *Request) GetHeader() http.Header {
	return r.HttpRequest.Header
}

func (r *Request) SetHeader(key string, value string) *Request {
	r.HttpRequest.Header.Set(key, value)
	return r
}

func (r *Request) AddHeader(key string, value string) *Request {
	r.HttpRequest.Header.Add(key, value)
	return r
}

func (r *Request) GetCookies() []*http.Cookie {
	return r.HttpRequest.Cookies()
}

func (r *Request) AddCookie(cookie *http.Cookie) *Request {
	r.HttpRequest.AddCookie(cookie)
	return r
}

func (r *Request) GetURL() string {
	return r.HttpRequest.URL.String()
}

func (r *Request) GetBody() []byte {
	if r.Body == nil {
		return nil
	}

	return r.Body
}

func (r *Request) SetBody(body io.Reader) *Request {
	var bodyBuffer, err = getBody(body)
	if err != nil {
		panic(err)
	}

	r.Body = bodyBuffer
	r.HttpRequest.Body = io.NopCloser(bytes.NewReader(bodyBuffer))

	return r
}

func (r *Request) Do() (*Response, error) {
	r.SetHeader("User-Agent", "vulnapi")

	rl.Take()
	httpRes, err := r.Client.Do(r.HttpRequest)
	if err != nil {
		return nil, err
	}

	res, err := NewResponse(httpRes)
	if err != nil {
		return nil, err
	}

	return res, err
}
