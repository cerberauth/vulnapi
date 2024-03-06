package discover

import (
	"net/url"
)

func ExtractBaseURL(inputURL *url.URL) *url.URL {
	baseURL := &url.URL{
		Scheme: inputURL.Scheme,
		Host:   inputURL.Host,
	}

	return baseURL
}
