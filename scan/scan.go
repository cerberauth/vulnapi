package scan

type ScanHandler func(url string, jwt string) []error

type Scan struct {
	Url          string
	ValidJwt     string
	PendingScans []ScanHandler
}

func NewScan(url string, valid_jwt string) *Scan {
	return &Scan{
		Url:      url,
		ValidJwt: valid_jwt,
	}
}

func (s *Scan) AddPendingScanHandler(sh ScanHandler) *Scan {
	s.PendingScans = append(s.PendingScans, sh)

	return s
}

func (s *Scan) Execute() ([]error, error) {
	if err := s.validateJwt(); err != nil {
		return nil, err
	}

	var errors []error
	for i := 0; i < len(s.PendingScans); i++ {
		errors = append(errors, s.PendingScans[i](s.Url, s.ValidJwt)...)
	}

	return errors, nil
}

func (s *Scan) validateJwt() error {
	return nil
}
