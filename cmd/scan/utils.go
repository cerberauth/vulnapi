package scan

import (
	"net/http"
	"strings"

	"github.com/cerberauth/vulnapi/internal/request"
)

func NewHTTPClientFromArgs(headersArg []string, httpCookiesArg []string) *request.Client {
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
			Value: parts[1],
		})
	}

	return request.NewClient(httpHeader, httpCookies)
}
