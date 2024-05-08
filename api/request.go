package api

type ScanOptions struct {
	Rate int `json:"rate"`
}

var DefaultScanOptions = &ScanOptions{
	Rate: 10,
}

func parseScanOptions(opts *ScanOptions) *ScanOptions {
	if opts == nil {
		return DefaultScanOptions
	}

	if opts.Rate == 0 {
		opts.Rate = DefaultScanOptions.Rate
	}

	return opts
}
