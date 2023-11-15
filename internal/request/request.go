package request

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
)

func NewRequest(method string, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "vulnapi/0.1")

	return req, nil
}

func DoRequest(client *http.Client, req *http.Request, ss auth.SecurityScheme) (*http.Request, *http.Response, error) {
	if ss != nil {
		for _, c := range ss.GetCookies() {
			req.AddCookie(c)
		}

		for n, h := range ss.GetHeaders() {
			req.Header.Add(n, h[0])
		}
	}

	res, err := client.Do(req)
	if err != nil {
		return req, res, err
	}
	defer res.Body.Close()

	return req, res, nil
}
