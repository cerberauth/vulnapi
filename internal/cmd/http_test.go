package cmd_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestNewHTTPClientFromArgs(t *testing.T) {
	rateArg := "10/s"
	proxyArg := "http://proxy.example.com"
	headersArg := []string{"Content-Type: application/json", "Authorization: Bearer token"}
	httpCookiesArg := []string{"session_id: abc123", "user_id: 123"}

	expectedRateLimit := 10
	expectedProxyURL, _ := url.Parse(proxyArg)
	expectedHTTPHeader := http.Header{}
	expectedHTTPHeader.Add("Content-Type", "application/json")
	expectedHTTPHeader.Add("Authorization", "Bearer token")
	expectedHTTPCookies := []*http.Cookie{
		{Name: "session_id", Value: "abc123"},
		{Name: "user_id", Value: "123"},
	}
	expectedClient := request.NewClient(request.NewClientOptions{
		RateLimit: expectedRateLimit,
		ProxyURL:  expectedProxyURL,
		Header:    expectedHTTPHeader,
		Cookies:   expectedHTTPCookies,
	})

	actualClient, err := cmd.NewHTTPClientFromArgs(rateArg, proxyArg, headersArg, httpCookiesArg)

	assert.NoError(t, err)
	assert.Equal(t, expectedClient.Timeout, actualClient.Timeout)
	assert.Equal(t, expectedClient.Header, actualClient.Header)
	assert.Equal(t, expectedClient.Cookies, actualClient.Cookies)
}

func TestNewHTTPClientFromArgsWhenRateLimitIsEmptyString(t *testing.T) {
	rateArg := ""
	proxyArg := "http://proxy.example.com"
	headersArg := []string{"Content-Type: application/json", "Authorization: Bearer token"}
	httpCookiesArg := []string{"session_id: abc123", "user_id: 123"}

	_, err := cmd.NewHTTPClientFromArgs(rateArg, proxyArg, headersArg, httpCookiesArg)

	assert.NoError(t, err)
}

func TestNewHTTPClientFromArgsWhenInvalidRateLimit(t *testing.T) {
	rateArg := "10/h"
	proxyArg := "http://proxy.example.com"
	headersArg := []string{"Content-Type: application/json", "Authorization: Bearer token"}
	httpCookiesArg := []string{"session_id: abc123", "user_id: 123"}

	_, err := cmd.NewHTTPClientFromArgs(rateArg, proxyArg, headersArg, httpCookiesArg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rate limit unit")
}

func TestNewHTTPClientFromArgsWhenInvalidProxyURL(t *testing.T) {
	rateArg := "10/s"
	proxyArg := "invalid"
	headersArg := []string{"Content-Type: application/json", "Authorization : Bearer token"}
	httpCookiesArg := []string{"session_id: abc123", "user_id: 123"}

	_, err := cmd.NewHTTPClientFromArgs(rateArg, proxyArg, headersArg, httpCookiesArg)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid proxy URL")
}
