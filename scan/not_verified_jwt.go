package scan

func NotVerifiedJwtScanHandler(url string, jwt string) []error {
	return nil
}

func (s *Scan) WithNotVerifiedJwtScan() *Scan {
	return s.AddPendingScanHandler(NotVerifiedJwtScanHandler)
}
