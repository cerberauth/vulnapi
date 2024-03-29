package scan

import "github.com/cerberauth/vulnapi/scan/jwt"

func (s *Scan) WithAlgNoneJwtScan() *Scan {
	return s.AddOperationScanHandler(jwt.AlgNoneJwtScanHandler)
}

func (s *Scan) WithNotVerifiedJwtScan() *Scan {
	return s.AddOperationScanHandler(jwt.NotVerifiedScanHandler)
}

func (s *Scan) WithJWTNullSignatureScan() *Scan {
	return s.AddOperationScanHandler(jwt.NullSignatureScanHandler)
}

func (s *Scan) WithWeakJwtSecretScan() *Scan {
	return s.AddOperationScanHandler(jwt.BlankSecretScanHandler).AddOperationScanHandler(jwt.WeakHMACSecretScanHandler)
}

func (s *Scan) WithAllVulnsScans() *Scan {
	return s.WithAlgNoneJwtScan().WithNotVerifiedJwtScan().WithJWTNullSignatureScan().WithWeakJwtSecretScan()
}
