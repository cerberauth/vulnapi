package generic_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/generic"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNoAuthOperationScanHandler(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: generic.NoAuthOperationVulnerabilityLevel,
		Name:          generic.NoAuthOperationVulnerabilityName,
		Description:   generic.NoAuthOperationVulnerabilityDescription,
		Operation:     operation,
	}

	report, err := generic.NoAuthOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestCheckNoAuthOperationScanHandlerWhenAuthConfigured(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	report, err := generic.NoAuthOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestAcceptUnauthenticatedOperationScanHandlerWhenNoAuthConfigured(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	report, err := generic.AcceptUnauthenticatedOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.False(t, report.HasVulnerabilityReport())
}

func TestAcceptUnauthenticatedOperationScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(204, nil))
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: generic.AcceptUnauthenticatedOperationVulnerabilityLevel,
		Name:          generic.AcceptUnauthenticatedOperationVulnerabilityName,
		Description:   generic.AcceptUnauthenticatedOperationVulnerabilityDescription,
		Operation:     operation,
	}

	report, err := generic.AcceptUnauthenticatedOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.HasVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}
