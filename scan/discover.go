package scan

import "github.com/cerberauth/vulnapi/scan/discover"

func (s *Scan) WithServerSignatureScan() *Scan {
	return s.AddScanHandler(discover.ServerSignatureScanHandler)
}

func (s *Scan) WithAllDiscoverScans() *Scan {
	return s.WithServerSignatureScan()
}
