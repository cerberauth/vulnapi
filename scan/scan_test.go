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

	s, err := scan.NewScan(operations, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: operations,
		Handlers:   []scan.ScanHandler{},
		Reporter:   report.NewReporter(),
	}, s)
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

	s, err := scan.NewScan(operations, reporter)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: operations,
		Handlers:   []scan.ScanHandler{},
		Reporter:   reporter,
	}, s)
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
