package scan_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewScanWithNoOperations(t *testing.T) {
	_, err := scan.NewScan(auth.Operations{}, nil)

	require.Error(t, err)
}

func TestNewScan(t *testing.T) {
	operations := auth.Operations{{
		Method:  "GET",
		Url:     "http://localhost:8080",
		Headers: &http.Header{},
		Cookies: []http.Cookie{},

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
	operations := auth.Operations{{
		Method:  "GET",
		Url:     "http://localhost:8080",
		Headers: &http.Header{},
		Cookies: []http.Cookie{},

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
