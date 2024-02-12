package scan

import "github.com/cerberauth/vulnapi/scan/jwt"

func (s *Scan) WithAlgNoneJwtScan() *Scan {
	return s.AddScanHandler(jwt.AlgNoneJwtScanHandler)
}

func (s *Scan) WithNotVerifiedJwtScan() *Scan {
	return s.AddScanHandler(jwt.NotVerifiedScanHandler)
}

func (s *Scan) WithJWTNullSignatureScan() *Scan {
	return s.AddScanHandler(jwt.NullSignatureScanHandler)
}

func (s *Scan) WithWeakJwtSecretScan() *Scan {
	return s.AddScanHandler(jwt.BlankSecretScanHandler).AddScanHandler(jwt.DictSecretScanHandler)
}

func (s *Scan) WithAllVulnsScans() *Scan {
	return s.WithAlgNoneJwtScan().WithNotVerifiedJwtScan().WithJWTNullSignatureScan().WithWeakJwtSecretScan()
}
