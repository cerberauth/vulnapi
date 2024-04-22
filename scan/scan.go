package scan

import (
	"fmt"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

type OperationScan struct {
	Operation *request.Operation
	Handler   ScanHandler
}

type ScanHandler func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error)

type Scan struct {
	Operations      request.Operations
	Reporter        *report.Reporter
	OperationsScans []OperationScan
}

func NewScan(operations request.Operations, reporter *report.Reporter) (*Scan, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("a scan must have at least one operation")
	}

	if reporter == nil {
		reporter = report.NewReporter()
	}

	return &Scan{
		Operations:      operations,
		Reporter:        reporter,
		OperationsScans: []OperationScan{},
	}, nil
}

func (s *Scan) GetOperationsScans() []OperationScan {
	return s.OperationsScans
}

func (s *Scan) AddOperationScanHandler(handler ScanHandler) *Scan {
	for _, operation := range s.Operations {
		s.OperationsScans = append(s.OperationsScans, OperationScan{
			Operation: operation,
			Handler:   handler,
		})
	}

	return s
}

func (s *Scan) AddScanHandler(handler ScanHandler) *Scan {
	s.OperationsScans = append(s.OperationsScans, OperationScan{
		Operation: s.Operations[0],
		Handler:   handler,
	})

	return s
}

func (s *Scan) Execute(scanCallback func(operationScan *OperationScan)) (*report.Reporter, []error, error) {
	if err := s.ValidateOperation(s.Operations[0]); err != nil {
		return nil, nil, err
	}

	if scanCallback == nil {
		scanCallback = func(operationScan *OperationScan) {}
	}

	var errors []error
	for _, scan := range s.OperationsScans {
		report, err := scan.Handler(scan.Operation, scan.Operation.SecuritySchemes[0]) // TODO: handle multiple security schemes
		if err != nil {
			errors = append(errors, err)
		}

		if report != nil {
			s.Reporter.AddReport(report)
		}

		scanCallback(&scan)
	}

	return s.Reporter, errors, nil
}

func (s *Scan) ValidateOperation(operation *request.Operation) error {
	attempt, err := scan.ScanURL(operation, &operation.SecuritySchemes[0]) // TODO: handle multiple security schemes
	if err != nil {
		return err
	}

	if attempt.Err != nil {
		return attempt.Err
	}

	if scan.DetectNotExpectedResponse(attempt.Response) == nil {
		fmt.Println("Operation validation failed because of unexpected response:", attempt.Response.StatusCode)
		fmt.Println("For better results, please make sure the first request is working as expected.")
		fmt.Println()
	}

	return nil
}

func (s *Scan) WithAllScans() *Scan {
	return s.WithAllVulnsScans().WithAllBestPracticesScans().WithAllDiscoverScans()
}
