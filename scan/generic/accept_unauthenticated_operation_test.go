package generic_test

import (
	"net/http"
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
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: generic.NoAuthOperationVulnerabilitySeverityLevel,

		OWASP2023Category: generic.NoAuthOperationVulnerabilityOWASP2023Category,

		ID:   generic.NoAuthOperationVulnerabilityID,
		Name: generic.NoAuthOperationVulnerabilityName,
		URL:  generic.NoAuthOperationVulnerabilityURL,
	}

	report, err := generic.NoAuthOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.HasFailedVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}

func TestCheckNoAuthOperationScanHandlerWhenAuthConfigured(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	report, err := generic.NoAuthOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.False(t, report.HasFailedVulnerabilityReport())
}

func TestAcceptUnauthenticatedOperationScanHandlerWhenNoAuthConfigured(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	report, err := generic.AcceptUnauthenticatedOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.False(t, report.HasFailedVulnerabilityReport())
}

func TestAcceptUnauthenticatedOperationScanHandler(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	vulnerabilityReport := report.VulnerabilityReport{
		SeverityLevel: generic.AcceptUnauthenticatedOperationVulnerabilitySeverityLevel,

		OWASP2023Category: generic.AcceptUnauthenticatedOperationVulnerabilityOWASP2023Category,

		ID:   generic.AcceptUnauthenticatedOperationVulnerabilityID,
		Name: generic.AcceptUnauthenticatedOperationVulnerabilityName,
		URL:  generic.AcceptUnauthenticatedOperationVulnerabilityURL,
	}

	report, err := generic.AcceptUnauthenticatedOperationScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.HasFailedVulnerabilityReport())
	assert.Equal(t, report.GetVulnerabilityReports()[0], &vulnerabilityReport)
}
