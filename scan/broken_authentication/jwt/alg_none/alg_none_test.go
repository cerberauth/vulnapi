package algnone_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	algnone "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/alg_none"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlgNoneJwtScanHandler_WithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestAlgNoneJwtScanHandler_Passed_WhenNoJWTAndUnauthorizedResponse(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", nil)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasPassed())
}

func TestAlgNoneJwtScanHandler_Passed_WhenUnauthorizedResponse(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasPassed())
}

func TestAlgNoneJwtScanHandler_Failed_WhenOKResponse(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasFailed())
}
