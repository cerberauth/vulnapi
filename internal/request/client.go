package request

import (
	"net/http"
	"time"
)

type Client struct {
	*http.Client
	Header  http.Header
	Cookies []*http.Cookie
}

var DefaultClient = NewClient(nil, nil)

func NewClient(header http.Header, cookies []*http.Cookie) *Client {
	if header == nil {
		header = http.Header{}
	}

	if cookies == nil {
		cookies = []*http.Cookie{}
	}

	return &Client{
		&http.Client{
			Timeout: 10 * time.Second,

			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
			},
		},
		header,
		cookies,
	}
}

func (c *Client) WithHTTPHeaders(header http.Header) *Client {
	c.Header = header
	return c
}

func (c *Client) WithCookies(cookies []*http.Cookie) *Client {
	c.Cookies = cookies
	return c
}
