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

func TestNewURLScan(t *testing.T) {
	s, err := scan.NewURLScan("GET", "http://localhost:8080", &http.Header{}, []http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:          "GET",
			Url:             "http://localhost:8080",
			Headers:         &http.Header{},
			Cookies:         []http.Cookie{},
			SecuritySchemes: []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}

func TestNewURLScanWithHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Add("Cache-Control", "no-cache")

	s, err := scan.NewURLScan("GET", "http://localhost:8080", &headers, []http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:          "GET",
			Url:             "http://localhost:8080",
			Headers:         &headers,
			Cookies:         []http.Cookie{},
			SecuritySchemes: []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}

func TestNewURLScanWithCookies(t *testing.T) {
	cookies := []http.Cookie{{
		Name:  "name",
		Value: "value",
	}}

	s, err := scan.NewURLScan("GET", "http://localhost:8080", &http.Header{}, cookies, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:          "GET",
			Url:             "http://localhost:8080",
			Headers:         &http.Header{},
			Cookies:         cookies,
			SecuritySchemes: []auth.SecurityScheme{auth.NewNoAuthSecurityScheme()},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}

func TestNewURLScanWithUpperCaseAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "Bearer token")
	token := "token"

	s, err := scan.NewURLScan("GET", "http://localhost:8080", &headers, []http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:  "GET",
			Url:     "http://localhost:8080",
			Headers: &headers,
			Cookies: []http.Cookie{},

			SecuritySchemes: []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("default", &token)},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}

func TestNewURLScanWithUpperCaseAuthorizationAndLowerCaseBearerHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "bearer token")
	token := "token"

	s, err := scan.NewURLScan("GET", "http://localhost:8080", &headers, []http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:  "GET",
			Url:     "http://localhost:8080",
			Headers: &headers,
			Cookies: []http.Cookie{},

			SecuritySchemes: []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("default", &token)},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}

func TestNewURLScanWithLowerCaseAuthorizationHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("authorization", "Bearer token")
	token := "token"

	s, err := scan.NewURLScan("GET", "http://localhost:8080", &headers, []http.Cookie{}, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:  "GET",
			Url:     "http://localhost:8080",
			Headers: &headers,
			Cookies: []http.Cookie{},

			SecuritySchemes: []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("default", &token)},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}
