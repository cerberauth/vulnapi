package scan

import "github.com/cerberauth/vulnapi/scan/discover"

func (s *Scan) WithServerSignatureScan() *Scan {
	return s.AddScanHandler(discover.ServerSignatureScanHandler)
}

func (s *Scan) WithDiscoverableOpenAPIScan() *Scan {
	return s.AddScanHandler(discover.DiscoverableOpenAPIScanHandler)
}

func (s *Scan) WithGraphQLIntrospectionScan() *Scan {
	return s.AddScanHandler(discover.GraphqlIntrospectionScanHandler)
}

func (s *Scan) WithAllDiscoverScans() *Scan {
	return s.WithServerSignatureScan().WithDiscoverableOpenAPIScan().WithGraphQLIntrospectionScan()
}
