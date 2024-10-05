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
		ScanOptions: &scan.ScanOptions{
			Reporter: report.NewReporter(),
		},

		Operations:      operations,
		OperationsScans: []scan.OperationScan{},
	}

	s, err := scan.NewScan(operations, nil)

	require.NoError(t, err)
	assert.Equal(t, expected.Operations, s.Operations)
	assert.Equal(t, expected.Reporter, s.Reporter)
	assert.Equal(t, expected.OperationsScans, s.OperationsScans)
}

func TestNewScanWithOptions(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	opts := &scan.ScanOptions{
		Reporter: report.NewReporter(),
	}
	expected := scan.Scan{
		ScanOptions: opts,

		Operations:      operations,
		OperationsScans: []scan.OperationScan{},
	}

	s, err := scan.NewScan(operations, opts)

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
	s.AddOperationScanHandler(scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return nil, nil
	}))

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, 1, len(operationsScans))
}

func TestScanExecuteWithNoHandlers(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithHandler(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"test-handler"},
	})
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithEmptyStringIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{""},
	})
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithMatchStringIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"category.*"},
	})
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}

func TestScanExecuteWithWrongMatchStringIncludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		IncludeScans: []string{"wrong-category.*"},
	})
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithExcludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"test-handler"},
	})
	handler := scan.NewOperationScanHandler("test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithMatchStringExcludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"category.*"},
	})
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 0, len(reporter.Reports))
}

func TestScanExecuteWithWrongMatchStringExcludeScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, &scan.ScanOptions{
		ExcludeScans: []string{"wrong-category.*"},
	})
	handler := scan.NewOperationScanHandler("category.test-handler", func(operation *request.Operation, ss auth.SecurityScheme) (*report.Report, error) {
		return &report.Report{ID: "test-report"}, nil
	})
	s.AddOperationScanHandler(handler)

	reporter, errors, err := s.Execute(nil)

	require.NoError(t, err)
	assert.Empty(t, errors)
	assert.Equal(t, 1, len(reporter.Reports))
	assert.Equal(t, "test-report", reporter.Reports[0].ID)
}
