package scan_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanWithNoOperations(t *testing.T) {
	_, err := scan.NewScan(operation.Operations{}, nil, nil)

	require.Error(t, err)
}

func TestNewScan(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	expected := scan.Scan{
		ScanOptions: &scan.ScanOptions{},
		Reporter:    report.NewReporter(),

		Operations:      operations,
		OperationsScans: []scan.OperationScan{},
	}

	s, err := scan.NewScan(operations, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, expected.Operations, s.Operations)
	assert.Equal(t, expected.Reporter, s.Reporter)
	assert.Equal(t, expected.OperationsScans, s.OperationsScans)
}

func TestNewScanWithOptions(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	opts := &scan.ScanOptions{}
	reporter := report.NewReporter()
	expected := scan.Scan{
		ScanOptions: opts,
		Reporter:    reporter,

		Operations:      operations,
		OperationsScans: []scan.OperationScan{},
	}

	s, err := scan.NewScan(operations, reporter, opts)

	require.NoError(t, err)
	assert.Equal(t, expected.Operations, s.Operations)
	assert.Equal(t, expected.Reporter, s.Reporter)
	assert.Equal(t, expected.OperationsScans, s.OperationsScans)
}

func TestScanGetOperationsScansWhenEmpty(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil, nil)

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, s.OperationsScans, operationsScans)
}

func TestScanGetOperationsScans(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil, nil)
	s.AddOperationScanHandler(scan.NewOperationScanHandler("test-handler", func(operation *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
		return nil, nil
	}, []report.Issue{}))

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, 1, len(operationsScans))
}

func TestScanExecuteWithNoHandlers(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil, nil)

	reporter, errors, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.GetScanReports()))
}

func TestScanExecuteWithHandler(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := operation.Operations{op}
	s, _ := scan.NewScan(operations, nil, nil)
	handler := scan.NewOperationScanHandler("test-handler", func(operation *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	}, []report.Issue{})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(context.TODO(), nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.GetScanReports()))
	assert.Equal(t, "test-report", reporter.GetScanReports()[0].ID)
}

func TestScanExecuteWithMultipleHandlersAndOptions(t *testing.T) {
	tests := []struct {
		name            string
		scanId          string
		potentialIssues []report.Issue
		opts            *scan.ScanOptions
		expected        struct {
			scanReportsLength int
		}
	}{
		{
			name:            "WithIncludeScansOptions",
			scanId:          "test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				IncludeScans: []string{"test-handler"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:            "WithEmptyStringIncludeScansOptions",
			scanId:          "test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				IncludeScans: []string{"test-handler"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:            "WithMatch string IncludeScans options",
			scanId:          "category.test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				IncludeScans: []string{"category.*"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:            "WithWrongMatchStringIncludeScansOptions",
			scanId:          "category.test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				IncludeScans: []string{"wrong-category.*"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 0,
			},
		},
		{
			name:            "WithExcludeScansOptions",
			scanId:          "test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				ExcludeScans: []string{"test-handler"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 0,
			},
		},
		{
			name:            "WithMatchStringExcludeScansOptions",
			scanId:          "category.test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				ExcludeScans: []string{"category.*"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 0,
			},
		},
		{
			name:            "WithWrongMatchStringExcludeScansOptions",
			scanId:          "category.test-handler",
			potentialIssues: []report.Issue{},
			opts: &scan.ScanOptions{
				ExcludeScans: []string{"wrong-category.*"},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:   "WithMinIssueSeverityOptionsAndPotentialIssuesBelowMinSeverity",
			scanId: "test-handler",
			potentialIssues: []report.Issue{
				{
					CVSS: report.CVSS{
						Score: 6.0,
					},
				},
			},
			opts: &scan.ScanOptions{
				MinIssueSeverity: 7.0,
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 0,
			},
		},
		{
			name:   "WithMinIssueSeverityOptionsAndPotentialIssuesAboveMinSeverity",
			scanId: "test-handler",
			potentialIssues: []report.Issue{
				{
					CVSS: report.CVSS{
						Score: 9.0,
					},
				},
			},
			opts: &scan.ScanOptions{
				MinIssueSeverity: 7.0,
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:   "WithIncludeCWEsOptions",
			scanId: "test-handler",
			potentialIssues: []report.Issue{
				{
					Classifications: &report.Classifications{
						CWE: report.CWE_1275_Sensitive_Cookie_With_Improper_SameSite,
					},
				},
			},
			opts: &scan.ScanOptions{
				IncludeCWEs: []string{string(report.CWE_1275_Sensitive_Cookie_With_Improper_SameSite)},
				ExcludeCWEs: []string{},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:   "WithExcludeCWEsOptions",
			scanId: "test-handler",
			potentialIssues: []report.Issue{
				{
					Classifications: &report.Classifications{
						CWE: report.CWE_1275_Sensitive_Cookie_With_Improper_SameSite,
					},
				},
			},
			opts: &scan.ScanOptions{
				IncludeCWEs: []string{},
				ExcludeCWEs: []string{string(report.CWE_1275_Sensitive_Cookie_With_Improper_SameSite)},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 0,
			},
		},
		{
			name:   "WithIncludeOWASPsOptions",
			scanId: "test-handler",
			potentialIssues: []report.Issue{
				{
					Classifications: &report.Classifications{
						OWASP: report.OWASP_2023_BOLA,
					},
				},
			},
			opts: &scan.ScanOptions{
				IncludeOWASPs: []string{string(report.OWASP_2023_BOLA)},
				ExcludeOWASPs: []string{},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
		{
			name:   "WithIncludeCWEsOptionsAndNilIssueClassifications",
			scanId: "test-handler",
			potentialIssues: []report.Issue{
				{
					CVSS: report.CVSS{
						Score: 9.0,
					},
				},
			},
			opts: &scan.ScanOptions{
				IncludeCWEs: []string{string(report.CWE_16_Configuration)},
			},
			expected: struct {
				scanReportsLength int
			}{
				scanReportsLength: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
			operations := operation.Operations{op}
			s, _ := scan.NewScan(operations, nil, tt.opts)
			scanReportID := "test-report"
			handler := scan.NewOperationScanHandler(tt.scanId, func(operation *operation.Operation, securityScheme *auth.SecurityScheme) (*report.ScanReport, error) {
				return &report.ScanReport{ID: scanReportID}, nil
			}, tt.potentialIssues)
			s.AddOperationScanHandler(handler)

			reporter, errors, err := s.Execute(context.TODO(), nil)

			require.NoError(t, err)
			assert.Empty(t, errors)
			assert.Equal(t, tt.expected.scanReportsLength, len(reporter.GetScanReports()))
			if tt.expected.scanReportsLength > 0 && len(reporter.GetScanReports()) > 0 {
				assert.Equal(t, scanReportID, reporter.GetScanReports()[0].ID)
			}
		})
	}
}
