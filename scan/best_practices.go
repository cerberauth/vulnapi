package scan

import (
	bestpractices "github.com/cerberauth/vulnapi/scan/best_practices"
)

func (s *Scan) WithHTTPHeadersBestPracticesScan() *Scan {
	return s.AddScanHandler(bestpractices.HTTPHeadersBestPracticesScanHandler)
}

func (s *Scan) WithHTTPTraceMethodBestPracticesScan() *Scan {
	return s.AddScanHandler(bestpractices.HTTPTraceMethodScanHandler)
}

func (s *Scan) WithServerSignatureScan() *Scan {
	return s.AddScanHandler(bestpractices.ServerSignatureScanHandler)
}

func (s *Scan) WithAllBestPracticesScans() *Scan {
	return s.WithHTTPHeadersBestPracticesScan().WithHTTPTraceMethodBestPracticesScan().WithServerSignatureScan()
}
