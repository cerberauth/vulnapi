package scan

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/x/telemetryx"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type ScanOptions struct {
	IncludeScans []string
	ExcludeScans []string
	Reporter     *report.Reporter
}

type Scan struct {
	*ScanOptions

	Operations      operation.Operations
	OperationsScans []OperationScan

	telemetryScanHandlerCounter   metric.Int64Counter
	telemetryOperationScanHandler metric.Int64Counter
}

const (
	otelName = "github.com/cerberauth/vulnapi/scan"

	otelScanIncludeScansAttribute = attribute.Key("include_scans")
	otelScanExcludeScansAttribute = attribute.Key("exclude_scans")
	otelScanHandlerIdAttribute    = attribute.Key("id")
)

func NewScan(operations operation.Operations, opts *ScanOptions) (*Scan, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("a scan must have at least one operation")
	}

	if opts == nil {
		opts = &ScanOptions{}
	}

	if opts.Reporter == nil {
		opts.Reporter = report.NewReporter()
	}

	telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
	telemetryScanCounter, _ := telemetryMeter.Int64Counter("scan.counter")
	telemetryScanHandlerCounter, _ := telemetryMeter.Int64Counter("scan.scan_handler.counter")
	telemetryOperationScanHandlerCounter, _ := telemetryMeter.Int64Counter("scan.operation_scan_handler.counter")
	telemetryScanCounter.Add(context.Background(), 1, metric.WithAttributes(
		otelScanIncludeScansAttribute.StringSlice(opts.IncludeScans),
		otelScanExcludeScansAttribute.StringSlice(opts.ExcludeScans),
	))

	return &Scan{
		ScanOptions: opts,

		Operations:      operations,
		OperationsScans: []OperationScan{},

		telemetryScanHandlerCounter:   telemetryScanHandlerCounter,
		telemetryOperationScanHandler: telemetryOperationScanHandlerCounter,
	}, nil
}

func (s *Scan) GetOperationsScans() []OperationScan {
	return s.OperationsScans
}

func (s *Scan) AddOperationScanHandler(handler *OperationScanHandler) *Scan {
	if !s.shouldAddScan(handler.ID) {
		return s
	}

	for _, operation := range s.Operations {
		s.OperationsScans = append(s.OperationsScans, OperationScan{
			Operation:   operation,
			ScanHandler: handler,
		})
	}

	s.telemetryOperationScanHandler.Add(context.Background(), int64(len(s.Operations)), metric.WithAttributes(
		otelScanHandlerIdAttribute.String(handler.ID),
	))

	return s
}

func (s *Scan) AddScanHandler(handler *OperationScanHandler) *Scan {
	if !s.shouldAddScan(handler.ID) {
		return s
	}

	s.OperationsScans = append(s.OperationsScans, OperationScan{
		Operation:   s.Operations[0],
		ScanHandler: handler,
	})

	s.telemetryOperationScanHandler.Add(context.Background(), 1, metric.WithAttributes(
		otelScanHandlerIdAttribute.String(handler.ID),
	))

	return s
}

func (s *Scan) Execute(ctx context.Context, scanCallback func(operationScan *OperationScan)) (*report.Reporter, []error, error) {
	if scanCallback == nil {
		scanCallback = func(operationScan *OperationScan) {}
	}

	var errors []error
	for _, scan := range s.OperationsScans {
		if scan.ScanHandler == nil {
			continue
		}

		securityScheme := scan.Operation.GetSecurityScheme() // TODO: handle multiple security schemes
		report, err := scan.ScanHandler.Handler(scan.Operation, securityScheme)
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

func (s *Scan) shouldAddScan(scanID string) bool {
	// Check if the scan should be excluded
	if len(s.ExcludeScans) > 0 && contains(s.ExcludeScans, scanID) {
		return false
	}

	// Check if the scan should be included
	if len(s.IncludeScans) > 0 && !contains(s.IncludeScans, scanID) {
		return false
	}

	return true
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
