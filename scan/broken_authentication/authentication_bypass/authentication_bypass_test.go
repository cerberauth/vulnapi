package authenticationbypass_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	authenticationbypass "github.com/cerberauth/vulnapi/scan/broken_authentication/authentication_bypass"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationByPassScanHandler_Skipped_WhenNoAuthSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/")

	report, err := authenticationbypass.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Vulns[0].HasBeenSkipped())
}

func TestAuthenticationByPassScanHandler_Failed_WhenAuthIsByPassed(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))

	report, err := authenticationbypass.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Vulns[0].HasFailed())
}

func TestAuthenticationByPassScanHandler_Passed_WhenAuthIsNotByPassed(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/")
	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := authenticationbypass.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Vulns[0].HasPassed())
}
