package scan_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanWithNoOperations(t *testing.T) {
	_, err := scan.NewScan(request.Operations{}, nil)

	require.Error(t, err)
}

func TestNewScan(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	expected := scan.Scan{
		Operations:      operations,
		Reporter:        report.NewReporter(),
		OperationsScans: []scan.OperationScan{},
	}

	s, err := scan.NewScan(operations, nil)

	require.NoError(t, err)
	assert.Equal(t, expected.Operations, s.Operations)
	assert.Equal(t, expected.Reporter, s.Reporter)
	assert.Equal(t, expected.OperationsScans, s.OperationsScans)
}

func TestNewScanWithReporter(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	reporter := report.NewReporter()
	expected := scan.Scan{
		Operations:      operations,
		Reporter:        reporter,
		OperationsScans: []scan.OperationScan{},
	}

	s, err := scan.NewScan(operations, reporter)

	require.NoError(t, err)
	assert.Equal(t, expected.Operations, s.Operations)
	assert.Equal(t, expected.Reporter, s.Reporter)
	assert.Equal(t, expected.OperationsScans, s.OperationsScans)
}

func TestScanGetOperationsScansWhenEmpty(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, s.OperationsScans, operationsScans)
}

func TestScanGetOperationsScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	s.AddOperationScanHandler(scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return nil, nil
	}))

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, 1, len(operationsScans))
}

func TestScanExecuteWithNoHandlers(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)

	reporter, errors, err := s.Execute(nil, nil, nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithHandler(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, nil, nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, []string{"test-handler"}, nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithMatchStringIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, []string{"category.*"}, nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithWrongMatchStringIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, []string{"wrong-category.*"}, nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithExcludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, nil, []string{"test-handler"})

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithMatchStringExcludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, nil, []string{"category.*"})

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithWrongMatchStringExcludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return &report.ScanReport{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil, nil, []string{"wrong-category.*"})

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}
