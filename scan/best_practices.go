package scan

import (
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
)

func (s *Scan) WithHTTPHeadersBestPracticesScan() *Scan {
	return s.AddOperationScanHandler(bestpractices.HTTPHeadersBestPracticesScanHandler)
}

func (s *Scan) WithHTTPTraceMethodBestPracticesScan() *Scan {
	return s.AddScanHandler(bestpractices.HTTPTraceMethodScanHandler)
}

func (s *Scan) WithHTTPTrackMethodBestPracticesScan() *Scan {
	return s.AddScanHandler(bestpractices.HTTPTrackMethodScanHandler)
}

func (s *Scan) WithHTTPCookiesBestPracticesScan() *Scan {
	return s.AddOperationScanHandler(bestpractices.HTTPCookiesScanHandler)
}

func (s *Scan) WithAllBestPracticesScans() *Scan {
	return s.WithHTTPHeadersBestPracticesScan().WithHTTPTraceMethodBestPracticesScan().WithHTTPTrackMethodBestPracticesScan().WithHTTPCookiesBestPracticesScan()
}
