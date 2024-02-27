package scan_test

import (
	"net/http"
	"testing"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenAPIScan(t *testing.T) {
	token := "token"
	s, err := scan.NewOpenAPIScan("../test/stub/simple_http_bearer_jwt.openapi.json", &token, nil)

	require.NoError(t, err)
	assert.Equal(t, &scan.Scan{
		Operations: request.Operations{{
			Method:  "GET",
			Url:     "http://localhost:8080/",
			Headers: &http.Header{},
			Cookies: []http.Cookie{},

			SecuritySchemes: []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("bearer_auth", &token)},
		}},
		Handlers: []scan.ScanHandler{},
		Reporter: report.NewReporter(),
	}, s)
}

func TestNewOpenAPIScanWithPathError(t *testing.T) {
	token := ""
	_, err := scan.NewOpenAPIScan("../test/stub/non_existing_file.openapi.json", &token, nil)

	require.Error(t, err)
}

func TestNewOpenAPIScanWithMultipleOperations(t *testing.T) {
	gofakeit.Seed(1)

	token := "token"
	securitySchemes := []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("bearer_auth", &token)}

	s, err := scan.NewOpenAPIScan("../test/stub/basic_http_bearer_jwt.openapi.json", &token, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, len(s.Operations))
	for _, s := range s.Operations {
		assert.Equal(t, s.SecuritySchemes, securitySchemes)
	}
}

func TestNewOpenAPIScanWithoutParamsExample(t *testing.T) {
	gofakeit.Seed(1)

	token := "token"
	securitySchemes := []auth.SecurityScheme{auth.NewAuthorizationBearerSecurityScheme("bearer_auth", &token)}

	s, err := scan.NewOpenAPIScan("../test/stub/basic_http_bearer_jwt.openapi.json", &token, nil)

	require.NoError(t, err)
	assert.Equal(t, 2, len(s.Operations))
	for _, s := range s.Operations {
		assert.Equal(t, s.SecuritySchemes, securitySchemes)
	}
}
