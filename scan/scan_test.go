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
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
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
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
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
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, s.OperationsScans, operationsScans)
}

func TestScanGetOperationsScans(t *testing.T) {
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	operations := request.Operations{operation}
	s, _ := scan.NewScan(operations, nil)
	s.AddOperationScanHandler(func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return nil, nil
	})

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, 1, len(operationsScans))
}
