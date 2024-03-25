package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

type ScanHandler func(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error)

type Scan struct {
	Operations request.Operations
	Reporter   *report.Reporter

	OperationHandlers []ScanHandler
	Handlers          []ScanHandler
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

func (s *Scan) AddOperationScanHandler(handler ScanHandler) *Scan {
	s.OperationHandlers = append(s.OperationHandlers, handler)

	return s
}

func (s *Scan) AddScanHandler(handler ScanHandler) *Scan {
	s.Handlers = append(s.Handlers, handler)

	return s
}

func (s *Scan) ExecuteOperation(operation *request.Operation, handlers []ScanHandler) ([]error, error) {
	var errors []error
	for _, handler := range handlers {
		report, err := handler(operation, operation.SecuritySchemes[0]) // TODO: handle multiple security schemes
		if err != nil {
			errors = append(errors, err)
		} else if report == nil {
			// Skip if no report
			continue
		}

		s.Reporter.AddReport(report)
	}

	return errors, nil
}

func (s *Scan) Execute() (*report.Reporter, []error, error) {
	operation := s.Operations[0]
	if err := s.ValidateOperation(operation); err != nil {
		return nil, nil, err
	}

	errors, err := s.ExecuteOperation(operation, s.Handlers)
	if err != nil {
		return nil, nil, err
	}

	for _, operation := range s.Operations {
		opErrors, opError := s.ExecuteOperation(operation, s.OperationHandlers)
		if opError != nil {
			return nil, nil, opError
		}

		errors = append(errors, opErrors...)
	}

	return s.Reporter, errors, nil
}

func (s *Scan) ValidateOperation(operation *request.Operation) error {
	securityScheme := operation.SecuritySchemes[0] // TODO: handle multiple security schemes
	attempt, err := scan.ScanURL(operation, &securityScheme)
	if err != nil {
		return err
	}

	if attempt.Err != nil {
		return attempt.Err
	}

	if scan.DetectNotExpectedResponse(attempt.Response) == nil {
		return fmt.Errorf("operation validation failed because of unexpected response: %d", attempt.Response.StatusCode)
	}

	return nil
}

func (s *Scan) WithAllScans() *Scan {
	return s.WithAllVulnsScans().WithAllBestPracticesScans().WithAllDiscoverScans()
}
