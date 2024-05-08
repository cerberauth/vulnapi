package request

import (
	"net/http"
	"time"

	"go.uber.org/ratelimit"
)

var rl = ratelimit.New(10)

var DefaultClient = NewClient(NewClientOptions{})

type Client struct {
	*http.Client
	Header  http.Header
	Cookies []*http.Cookie
}

type NewClientOptions struct {
	Timeout time.Duration
	Rate    int // requests per second

	Header  http.Header
	Cookies []*http.Cookie
}

func NewClient(opts NewClientOptions) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	if opts.Rate > 0 {
		rl = ratelimit.New(opts.Rate)
	}

	if opts.Header == nil {
		opts.Header = http.Header{}
	}

	if opts.Cookies == nil {
		opts.Cookies = []*http.Cookie{}
	}

	return &Client{
		&http.Client{
			Timeout: 10 * time.Second,

			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
			},
		},
		opts.Header,
		opts.Cookies,
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
