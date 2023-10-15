package scan

import "github.com/cerberauth/vulnapi/scan/jwt"

func (s *Scan) WithAlgNoneJwtScan() *Scan {
	return s.AddPendingScanHandler(jwt.AlgNoneJwtScanHandler)
}

func (s *Scan) WithNotVerifiedJwtScan() *Scan {
	return s.AddPendingScanHandler(jwt.NotVerifiedScanHandler)
}

func (s *Scan) WithJWTNullSignatureScan() *Scan {
	return s.AddPendingScanHandler(jwt.NullSignatureScanHandler)
}

func (s *Scan) WithWeakJwtSecretScan() *Scan {
	return s.AddPendingScanHandler(jwt.BlankSecretScanHandler).AddPendingScanHandler(jwt.DictSecretScanHandler)
}

func (s *Scan) WithAllScans() *Scan {
	return s.WithAlgNoneJwtScan().WithNotVerifiedJwtScan().WithJWTNullSignatureScan().WithWeakJwtSecretScan()
}
