package generic_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/generic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckAcceptUnauthenticatedOperation(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)
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
