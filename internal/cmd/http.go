package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cerberauth/vulnapi/internal/request"
)

func parseRateLimit(rateLimit string) (int, error) {
	parts := strings.Split(rateLimit, "/")
	num, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	if len(parts) == 1 {
		return num, nil
	} else if len(parts) != 2 {
		return 0, fmt.Errorf("invalid rate limit format")
	}

	switch parts[1] {
	case "s":
		return num, nil
	case "m":
		return num / 60, nil
	default:
		return 0, fmt.Errorf("invalid rate limit unit")
	}
}

func NewHTTPClientFromArgs(rateLimitArg string, proxyArg string, headersArg []string, httpCookiesArg []string, insecureArg bool) (*request.Client, error) {
	if rateLimitArg == "" {
		rateLimitArg = defaultRateLimit
	}

	rateLimit, err := parseRateLimit(rateLimitArg)
	if err != nil {
		return nil, err
	}

	httpHeader := http.Header{}
	for _, h := range headersArg {
		parts := strings.SplitN(h, ":", 2)
		httpHeader.Add(parts[0], strings.TrimLeft(parts[1], " "))
	}

	var httpCookies []*http.Cookie
	for _, c := range httpCookiesArg {
		parts := strings.SplitN(c, ":", 2)
		httpCookies = append(httpCookies, &http.Cookie{
			Name:  parts[0],
			Value: strings.TrimLeft(parts[1], " "),
		})
	}

	var proxyURL *url.URL
	if proxyArg != "" {
		proxyURL, err = url.Parse(proxyArg)
		if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
			return nil, errors.New("invalid proxy URL")
		}
	}

	return request.NewClient(request.NewClientOptions{
		RateLimit:   rateLimit,
		ProxyURL:    proxyURL,
		InsecureTLS: insecureArg,

		Header:  httpHeader,
		Cookies: httpCookies,
	}), nil
}
