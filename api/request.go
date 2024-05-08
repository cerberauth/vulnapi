package api

import (
	"net/url"

	"github.com/cerberauth/vulnapi/internal/request"
)

type ScanOptions struct {
	Rate     int    `json:"rate"`
	ProxyURL string `json:"proxy"`
}

func parseScanOptions(opts *ScanOptions) request.NewClientOptions {
	if opts == nil {
		opts = &ScanOptions{}
	}

	var proxyURL *url.URL
	if opts.ProxyURL != "" {
		proxyURL, _ = url.Parse(opts.ProxyURL)
	}

	return request.NewClientOptions{
		Rate:     opts.Rate,
		ProxyURL: proxyURL,

		Header:  nil,
		Cookies: nil,
	}
}
