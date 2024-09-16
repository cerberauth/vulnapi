package scan

import (
	"fmt"
	"regexp"

	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

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

func (s *Scan) AddOperationScanHandler(handler *OperationScanHandler) *Scan {
	for _, operation := range s.Operations {
		s.OperationsScans = append(s.OperationsScans, OperationScan{
			Operation:   operation,
			ScanHandler: handler,
		})
	}

	return s
}

func (s *Scan) AddScanHandler(handler *OperationScanHandler) *Scan {
	s.OperationsScans = append(s.OperationsScans, OperationScan{
		Operation:   s.Operations[0],
		ScanHandler: handler,
	})

	return s
}

func (s *Scan) Execute(scanCallback func(operationScan *OperationScan), includeScans []string, excludeScans []string) (*report.Reporter, []error, error) {
	if scanCallback == nil {
		scanCallback = func(operationScan *OperationScan) {}
	}

	var errors []error
	for _, scan := range s.OperationsScans {
		if scan.ScanHandler == nil {
			continue
		}

		// Check if the scan should be excluded
		if len(excludeScans) > 0 && contains(excludeScans, scan.ScanHandler.ID) {
			continue
		}

		// Check if the scan should be included
		if len(includeScans) > 0 && !contains(includeScans, scan.ScanHandler.ID) {
			continue
		}

		report, err := scan.ScanHandler.Handler(scan.Operation, scan.Operation.SecuritySchemes[0]) // TODO: handle multiple security schemes
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

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}

		match, _ := regexp.MatchString(s, item)
		if match {
			return true
		}
	}
	return false
}
