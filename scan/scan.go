package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

type ScanHandler func(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error)

type Scan struct {
	Operations request.Operations
	Handlers   []ScanHandler
	Reporter   *report.Reporter
}

func NewScan(operations request.Operations, reporter *report.Reporter) (*Scan, error) {
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

func (s *Scan) ExecuteOperation(operation *request.Operation) ([]error, error) {
	if len(operation.SecuritySchemes) == 0 {
		return nil, fmt.Errorf("no security schemes has been configured")
	}

	var errors []error
	for _, handler := range s.Handlers {
		report, err := handler(operation, operation.SecuritySchemes[0]) // TODO: handle multiple security schemes

		if err != nil {
			errors = append(errors, err)
		}

		s.Reporter.AddReport(report)
	}

	return errors, nil
}

func (s *Scan) ValidateOperation(operation *request.Operation) error {
	if len(operation.SecuritySchemes) == 0 {
		return fmt.Errorf("no security schemes has been configured")
	}

	attempt, err := request.ScanURL(operation, &operation.SecuritySchemes[0])
	if err != nil {
		return err
	}

	if attempt.Err != nil {
		return attempt.Err
	}

	return nil
}
