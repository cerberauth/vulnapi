package api

import (
	"net/url"

	"github.com/cerberauth/vulnapi/internal/request"
)

type ScanOptions struct {
	RateLimit int    `json:"rateLimit"`
	ProxyURL  string `json:"proxy"`

	Scans         []string `json:"scans"`
	ExcludeScans  []string `json:"excludeScans"`
	MinSeverity   float64  `json:"minSeverity"`
	IncludeCWEs   []string `json:"includeCWEs"`
	ExcludeCWEs   []string `json:"excludeCWEs"`
	IncludeOWASPs []string `json:"includeOWASPs"`
	ExcludeOWASPs []string `json:"excludeOWASPs"`
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
		RateLimit: opts.RateLimit,
		ProxyURL:  proxyURL,

		Header:  nil,
		Cookies: nil,
	}
}
