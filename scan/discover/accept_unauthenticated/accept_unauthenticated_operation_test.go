package acceptunauthenticated_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	acceptunauthenticated "github.com/cerberauth/vulnapi/scan/discover/accept_unauthenticated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcceptUnauthenticatedScanHandler_Failed_WhenNoAuthSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := acceptunauthenticated.ScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.True(t, report.Vulns[0].HasFailed())
}

func TestCheckNoAuthOperationScanHandler_Passed_WhenAuthConfigured(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := acceptunauthenticated.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Vulns[0].HasPassed())
}
