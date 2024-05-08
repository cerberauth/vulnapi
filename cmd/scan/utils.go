package scan

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/cerberauth/vulnapi/internal/request"
)

func parseRate(rate string) (int, error) {
	parts := strings.Split(rate, "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid rate format")
	}

	num, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	switch parts[1] {
	case "s":
		return num, nil
	case "m":
		return num / 60, nil
	default:
		return 0, fmt.Errorf("invalid rate unit")
	}
}

func NewHTTPClientFromArgs(rateArg string, proxyArg string, headersArg []string, httpCookiesArg []string) *request.Client {
	rate, _ := parseRate(rateArg)

	var proxyURL *url.URL
	if proxyArg != "" {
		proxyURL, _ = url.Parse(proxyArg)
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

	return request.NewClient(request.NewClientOptions{
		Rate:     rate,
		ProxyURL: proxyURL,

		Header:  httpHeader,
		Cookies: httpCookies,
	})
}
