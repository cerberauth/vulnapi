package scan

import (
	"errors"
	"fmt"

	"github.com/cerberauth/vulnapi/internal/request"
)

type ScanHandler func(url string, jwt string) []error

type Scan struct {
	Url          string
	ValidJwt     *string
	PendingScans []ScanHandler
}

func NewScanner(url string, valid_jwt *string) *Scan {
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
	if err := s.ValidateRequest(); err != nil {
		return nil, err
	}

	var errors []error
	for i := 0; i < len(s.PendingScans); i++ {
		errors = append(errors, s.PendingScans[i](s.Url, *s.ValidJwt)...)
	}

	return errors, nil
}

func (s *Scan) ValidateRequest() error {
	if s.ValidJwt == nil {
		return errors.New("no valid JWT provided")
	}

	statusCode, _, err := request.SendRequestWithBearerAuth(s.Url, *s.ValidJwt)
	if err != nil {
		return fmt.Errorf("request with url %s has an unexpected error", err)
	}

	if statusCode < 200 && statusCode >= 300 {
		return fmt.Errorf("unexpected status code %d during test request", statusCode)
	}

	return nil
}
