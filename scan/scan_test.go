package scan_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanWithNoOperations(t *testing.T) {
	_, err := scan.NewScan(request.Operations{}, nil)

	require.Error(t, err)
}

func TestNewScan(t *testing.T) {
	operations := request.Operations{{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "localhost:8080", Path: "/"},
			Header: http.Header{},
		},

		SecuritySchemes: []auth.SecurityScheme{},
	}}
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
	operations := request.Operations{{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "localhost:8080", Path: "/"},
			Header: http.Header{},
		},

		SecuritySchemes: []auth.SecurityScheme{},
	}}
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
	operations := request.Operations{{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "localhost:8080", Path: "/"},
			Header: http.Header{},
		},

		SecuritySchemes: []auth.SecurityScheme{},
	}}
	s, _ := scan.NewScan(operations, nil)

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, s.OperationsScans, operationsScans)
}

func TestScanGetOperationsScans(t *testing.T) {
	operations := request.Operations{{
		Request: &http.Request{
			Method: "GET",
			URL:    &url.URL{Scheme: "http", Host: "localhost:8080", Path: "/"},
			Header: http.Header{},
		},

		SecuritySchemes: []auth.SecurityScheme{},
	}}
	s, _ := scan.NewScan(operations, nil)
	s.AddOperationScanHandler(func(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
		return nil, nil
	})

	operationsScans := s.GetOperationsScans()

	assert.Equal(t, 1, len(operationsScans))
}

func TestScanValidateOperation(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(httpmock.NewStringResponse(200, "OK")))

	s, err := scan.NewURLScan(operation.Method, operation.RequestURI, nil, nil, nil)

	err = s.ValidateOperation(operation)
	assert.NoError(t, err)
}

func TestScanValidateOperationWhenRequestHasInternalServerError(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromResponse(httpmock.NewStringResponse(500, "Internal Server Error")))

	s, err := scan.NewURLScan(operation.Method, operation.RequestURI, nil, nil, nil)

	err = s.ValidateOperation(operation)
	assert.Error(t, err)
}
