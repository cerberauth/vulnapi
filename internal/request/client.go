package request

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"golang.org/x/time/rate"
)

var rl = rate.NewLimiter(rate.Every(100*time.Millisecond), 1) // 10 req/s default

// Wait blocks until the package-level rate limiter allows another request.
// Callers that send HTTP requests outside of a Client method (e.g. via
// probe.Do) should call this first to keep proactive rate limiting.
func Wait(ctx context.Context) error {
	return rl.Wait(ctx)
}

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

// DefaultUserAgent is sent when neither the client nor the request sets a
// User-Agent.
const DefaultUserAgent = "vulnapi"

type Client struct {
	*http.Client
	Header  http.Header
	Cookies []*http.Cookie

	// UserAgent is the default User-Agent, overridden by a User-Agent in
	// Header (e.g. from -A or -H). DefaultUserAgent is used when empty.
	UserAgent string
}

type NewClientOptions struct {
	Timeout            time.Duration
	RateLimit          int // requests per second
	ProxyURL           *url.URL
	InsecureSkipVerify bool

	Header  http.Header
	Cookies []*http.Cookie
}

func NewClientFromHTTPClient(httpClient *http.Client, limiter *rate.Limiter) *Client {
	if limiter != nil {
		rl = limiter
	}

	return &Client{
		Client:  httpClient,
		Header:  http.Header{},
		Cookies: []*http.Cookie{},
	}
}

func NewClient(opts NewClientOptions) *Client {
	var proxy func(*http.Request) (*url.URL, error)
	if opts.ProxyURL != nil && opts.ProxyURL.String() != "" {
		proxy = http.ProxyURL(opts.ProxyURL)
	} else {
		proxy = http.ProxyFromEnvironment
	}

	transport := &http.Transport{
		Proxy: proxy,

		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
	}
	if opts.InsecureSkipVerify {
		//nolint:gosec
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	if opts.RateLimit > 0 {
		rl = rate.NewLimiter(rate.Every(time.Second/time.Duration(opts.RateLimit)), 1)
	}

	if opts.Header == nil {
		opts.Header = http.Header{}
	}

	if opts.Cookies == nil {
		opts.Cookies = []*http.Cookie{}
	}

	return &Client{
		Client: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
		},
		Header:  opts.Header,
		Cookies: opts.Cookies,
	}
}

func (c *Client) WithUserAgent(userAgent string) *Client {
	c.UserAgent = userAgent
	return c
}

func (c *Client) GetUserAgent() string {
	if c.UserAgent == "" {
		return DefaultUserAgent
	}
	return c.UserAgent
}

func (c *Client) WithHeader(header http.Header) *Client {
	c.Header = header
	return c
}

func (c *Client) WithCookies(cookies []*http.Cookie) *Client {
	c.Cookies = cookies
	return c
}

func (c *Client) ClearSecurityScheme(securityScheme *auth.SecurityScheme) *Client {
	// delete security schemes headers and cookies when name and value are the same
	for k, v := range securityScheme.GetHeaders() {
		if len(v) > 0 && c.Header.Get(k) == v[0] {
			c.Header.Del(k)
		}
	}

	for _, sc := range securityScheme.GetCookies() {
		c.Cookies = slices.DeleteFunc(c.Cookies, func(cookie *http.Cookie) bool {
			return cookie.Name == sc.Name && cookie.Value == sc.Value
		})
	}
	return c
}

func (c *Client) ClearSecuritySchemes(securitySchemes []*auth.SecurityScheme) *Client {
	for _, securityScheme := range securitySchemes {
		c.ClearSecurityScheme(securityScheme)
	}
	return c
}
