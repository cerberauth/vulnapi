package scan

import (
	"errors"

	"github.com/cerberauth/vulnapi/report"
	restapi "github.com/cerberauth/vulnapi/scan/rest_api"
)

type ScanHandler func(url string, jwt string) (*report.ScanReport, error)

type Scan struct {
	url          string
	validJwt     *string
	pendingScans []ScanHandler
	reporter     *report.Reporter
}

func NewScanner(url string, valid_jwt *string) *Scan {
	return &Scan{
		reporter: report.NewReporter(),
		url:      url,
		validJwt: valid_jwt,
	}
}

func (s *Scan) AddPendingScanHandler(sh ScanHandler) *Scan {
	s.pendingScans = append(s.pendingScans, sh)

	return s
}

func (s *Scan) Execute() (*report.Reporter, []error, error) {
	if err := s.ValidateRequest(); err != nil {
		return nil, nil, err
	}

	var errors []error
	for i := 0; i < len(s.pendingScans); i++ {
		rep, err := s.pendingScans[i](s.url, *s.validJwt)

		if err != nil {
			errors = append(errors, err)
		} else if rep != nil {
			s.reporter.AddReport(rep)
		}
	}

	return s.reporter, errors, nil
}

func (s *Scan) ValidateRequest() error {
	if s.validJwt == nil {
		return errors.New("no valid JWT provided")
	}

	r := restapi.ScanRestAPI(s.url, *s.validJwt)
	if r.Err != nil {
		return r.Err
	}

	return nil
}
