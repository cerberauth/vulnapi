package scan

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type ScanOptions struct {
	IncludeScans []string
	ExcludeScans []string

	MinIssueSeverity float64
	IncludeCWEs      []string
	ExcludeCWEs      []string
	IncludeOWASPs    []string
	ExcludeOWASPs    []string
}

type Scan struct {
	*ScanOptions
	Reporter *report.Reporter

	Operations      operation.Operations
	OperationsScans []OperationScan
}

var tracer = otel.Tracer("scan")

func NewScan(operations operation.Operations, reporter *report.Reporter, opts *ScanOptions) (*Scan, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("a scan must have at least one operation")
	}

	if opts == nil {
		opts = &ScanOptions{}
	}

	if reporter == nil {
		reporter = report.NewReporter()
	}

	return &Scan{
		ScanOptions: opts,
		Reporter:    reporter,

		Operations:      operations,
		OperationsScans: []OperationScan{},
	}, nil
}

func (s *Scan) GetOperationsScans() []OperationScan {
	return s.OperationsScans
}

func (s *Scan) AddOperationScanHandler(handler *OperationScanHandler) *Scan {
	if !s.shouldAddScan(handler) {
		return s
	}

	for _, operation := range s.Operations {
		s.OperationsScans = append(s.OperationsScans, OperationScan{
			Operation:   operation,
			ScanHandler: handler,
		})
	}
	return s
}

func (s *Scan) AddScanHandler(handler *OperationScanHandler) *Scan {
	if !s.shouldAddScan(handler) {
		return s
	}

	s.OperationsScans = append(s.OperationsScans, OperationScan{
		Operation:   s.Operations[0],
		ScanHandler: handler,
	})
	return s
}

func (s *Scan) Execute(ctx context.Context, scanCallback func(operationScan *OperationScan)) (*report.Reporter, []error, error) {
	ctx, span := tracer.Start(ctx, "Execute Scan")
	defer span.End()

	if scanCallback == nil {
		scanCallback = func(operationScan *OperationScan) {}
	}

	var errors []error
	for _, scan := range s.OperationsScans {
		if scan.ScanHandler == nil {
			continue
		}

		operationCtx, operationSpan := tracer.Start(ctx, "Operation Scan")
		operationSpan.SetAttributes(
			attribute.String("method", scan.Operation.Method),
			attribute.String("handler", scan.ScanHandler.ID),
		)

		securityScheme := scan.Operation.SecuritySchemes[0] // TODO: handle multiple security schemes
		_, operationSecuritySchemeSpan := tracer.Start(operationCtx, "Using Security Scheme")
		operationSecuritySchemeSpan.SetAttributes(
			attribute.String("name", auth.GetSecuritySchemeUniqueName(securityScheme)),
			attribute.String("type", string(securityScheme.GetType())),
			attribute.String("scheme", string(securityScheme.GetScheme())),
		)

		report, err := scan.ScanHandler.Handler(scan.Operation, securityScheme)
		if err != nil {
			operationSpan.RecordError(err)
			errors = append(errors, err)
		}

		if report != nil {
			s.Reporter.AddReport(report)
		}

		scanCallback(&scan)
		operationSecuritySchemeSpan.End()
		operationSpan.End()
	}

	s.Reporter.Options.ScansIncluded = s.IncludeScans
	s.Reporter.Options.ScansExcluded = s.ExcludeScans
	s.Reporter.Options.MinIssueSeverity = s.MinIssueSeverity
	s.Reporter.Options.CWEsIncluded = s.IncludeCWEs
	s.Reporter.Options.CWEsExcluded = s.ExcludeCWEs
	s.Reporter.Options.OWASPsIncluded = s.IncludeOWASPs
	s.Reporter.Options.OWASPsExcluded = s.ExcludeOWASPs

	return s.Reporter, errors, nil
}

func (s *Scan) shouldAddScan(handler *OperationScanHandler) bool {
	// Check if the scan should be excluded
	if len(s.ExcludeScans) > 0 && contains(s.ExcludeScans, handler.ID) {
		return false
	}

	// Check if the scan should be included
	if len(s.IncludeScans) > 0 && !contains(s.IncludeScans, handler.ID) {
		return false
	}

	for _, issue := range handler.PotentialIssues {
		// Check if the scan's potential issues match the min severity
		if issue.CVSS.Score < s.MinIssueSeverity {
			return false
		}

		if issue.Classifications == nil {
			continue
		}

		// Check if the scan's potential issues match CWE classification
		if len(s.IncludeCWEs) > 0 && !contains(s.IncludeCWEs, string(issue.Classifications.CWE)) {
			return false
		}

		if len(s.ExcludeCWEs) > 0 && contains(s.ExcludeCWEs, string(issue.Classifications.CWE)) {
			return false
		}

		// Check if the scan's potential issues match OWASP classification
		if len(s.IncludeOWASPs) > 0 && !contains(s.IncludeOWASPs, string(issue.Classifications.OWASP)) {
			return false
		}

		if len(s.ExcludeOWASPs) > 0 && !contains(s.ExcludeOWASPs, string(issue.Classifications.OWASP)) {
			return false
		}
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
