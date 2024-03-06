package scan

import (
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
)

func (s *Scan) WithHTTPHeadersBestPracticesScan() *Scan {
	return s.AddOperationScanHandler(bestpractices.HTTPHeadersBestPracticesScanHandler)
}

func (s *Scan) WithHTTPTraceMethodBestPracticesScan() *Scan {
	return s.AddOperationScanHandler(bestpractices.HTTPTraceMethodScanHandler)
}

func (s *Scan) WithHTTPCookiesBestPracticesScan() *Scan {
	return s.AddOperationScanHandler(bestpractices.HTTPCookiesScanHandler)
}

func (s *Scan) WithAllBestPracticesScans() *Scan {
	return s.WithHTTPHeadersBestPracticesScan().WithHTTPTraceMethodBestPracticesScan().WithHTTPCookiesBestPracticesScan()
}
