package request

import (
	"net/http"
	"net/url"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"go.uber.org/ratelimit"
)

var rl = ratelimit.New(10)

var defaultClient *Client = nil

func GetDefaultClient() *Client {
	if defaultClient == nil {
		defaultClient = NewClient(NewClientOptions{})
	}

	return defaultClient
}

func SetDefaultClient(client *Client) {
	defaultClient = client
}

type Client struct {
	*http.Client
	Header  http.Header
	Cookies []*http.Cookie
}

type NewClientOptions struct {
	Timeout   time.Duration
	RateLimit int // requests per second
	ProxyURL  *url.URL

	Header  http.Header
	Cookies []*http.Cookie
}

func NewClient(opts NewClientOptions) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	if opts.RateLimit > 0 {
		rl = ratelimit.New(opts.RateLimit)
	}

	if opts.Header == nil {
		opts.Header = http.Header{}
	}

	if opts.Cookies == nil {
		opts.Cookies = []*http.Cookie{}
	}

	var proxy func(*http.Request) (*url.URL, error)
	if opts.ProxyURL != nil && opts.ProxyURL.String() != "" {
		proxy = http.ProxyURL(opts.ProxyURL)
	} else {
		proxy = http.ProxyFromEnvironment
	}

	return &Client{
		&http.Client{
			Timeout: opts.Timeout,

			Transport: &http.Transport{
				Proxy: proxy,

				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
			},
		},
		opts.Header,
		opts.Cookies,
	}
}

func (c *Client) WithHeader(header http.Header) *Client {
	c.Header = header
	return c
}

func (c *Client) WithCookies(cookies []*http.Cookie) *Client {
	c.Cookies = cookies
	return c
}

func removeCookie(cookies []*http.Cookie, cookie *http.Cookie) []*http.Cookie {
	for i, c := range cookies {
		if c == cookie {
			return append(cookies[:i], cookies[i+1:]...)
		}
	}
	return cookies
}

func (c *Client) ClearSecurityScheme(securityScheme *auth.SecurityScheme) *Client {
	// delete security schemes headers and cookies when name and value are the same
	for k, v := range securityScheme.GetHeaders() {
		if c.Header.Get(k) == v[0] {
			c.Header.Del(k)
		}
	}

	for _, sc := range securityScheme.GetCookies() {
		for _, cookie := range c.Cookies {
			if cookie.Name == sc.Name && cookie.Value == sc.Value {
				c.Cookies = removeCookie(c.Cookies, cookie)
			}
		}
	}
	return c
}

func (c *Client) ClearSecuritySchemes(securitySchemes []*auth.SecurityScheme) *Client {
	for _, securityScheme := range securitySchemes {
		c.ClearSecurityScheme(securityScheme)
	}
	return c
}
