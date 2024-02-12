package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
)

type ScanHandler func(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error)

type Scan struct {
	Operations auth.Operations
	Handlers   []ScanHandler
	Reporter   *report.Reporter
}

func NewScan(operations auth.Operations, reporter *report.Reporter) (*Scan, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("a scan must have at least one operation")
	}

	if reporter == nil {
		reporter = report.NewReporter()
	}

	return &Scan{
		Operations: operations,
		Handlers:   []ScanHandler{},
		Reporter:   reporter,
	}, nil
}

func (s *Scan) AddScanHandler(sh ScanHandler) *Scan {
	s.Handlers = append(s.Handlers, sh)

	return s
}

func (s *Scan) Execute() (*report.Reporter, []error, error) {
	if len(s.Operations) == 0 {
		return nil, nil, fmt.Errorf("no operations has been configured before executing scan")
	}

	if err := s.ValidateOperation(&s.Operations[0]); err != nil {
		return nil, nil, err
	}

	var errors []error
	for _, o := range s.Operations {
		opErrors, opError := s.ExecuteOperation(&o)
		if opError != nil {
			return nil, nil, opError
		}

		errors = append(errors, opErrors...)
	}

	return s.Reporter, errors, nil
}

func (s *Scan) ExecuteOperation(o *auth.Operation) ([]error, error) {
	if len(o.SecuritySchemes) == 0 {
		return nil, fmt.Errorf("no security schemes has been configured")
	}

	var errors []error
	for _, handler := range s.Handlers {
		rep, err := handler(o, o.SecuritySchemes[0])

		if err != nil {
			errors = append(errors, err)
		}

		s.Reporter.AddReport(rep)
	}

	return errors, nil
}

func (s *Scan) ValidateOperation(o *auth.Operation) error {
	if len(o.SecuritySchemes) == 0 {
		return fmt.Errorf("no security schemes has been configured")
	}

	r := restapi.ScanRestAPI(o, o.SecuritySchemes[0])
	if r.Err != nil {
		return r.Err
	}

	if r.Response.StatusCode >= 300 {
		return fmt.Errorf("the request with the passed JWT should return 2xx status code")
	}

	return nil
}
