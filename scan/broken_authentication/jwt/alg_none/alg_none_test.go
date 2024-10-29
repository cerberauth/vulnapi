package algnone_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	algnone "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/alg_none"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlgNoneJwtScanHandler_WithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 0, len(report.GetScanAttempts()))
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestAlgNoneJwtScanHandler_Passed_WhenNoJWTAndUnauthorizedResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", nil)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 4, len(report.GetScanAttempts()))
	assert.Nil(t, report.GetData())
	assert.True(t, report.Issues[0].HasPassed())
}

func TestAlgNoneJwtScanHandler_Passed_WhenUnauthorizedResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := algnone.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 4, len(report.GetScanAttempts()))
	assert.True(t, report.Issues[0].HasPassed())
}

func TestAlgNoneJwtScanHandler_Failed_WhenOKResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := algnone.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(*algnone.AlgNoneData)

	require.NoError(t, err)
	assert.Equal(t, 1, len(report.GetScanAttempts()))
	assert.NotNil(t, data)
	assert.Equal(t, "none", data.Alg)
	assert.True(t, report.Issues[0].HasFailed())
}

func TestAlgNoneJwtScanHandler_Failed_WhenOKResponseAndAlgNone(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), func(req *http.Request) (*http.Response, error) {
		switch req.Header.Get("Authorization") {
		case "Bearer eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.":
			return httpmock.NewBytesResponder(http.StatusOK, nil)(req)
		default:
			return httpmock.NewBytesResponder(http.StatusUnauthorized, nil)(req)
		}
	})

	report, err := algnone.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(*algnone.AlgNoneData)

	require.NoError(t, err)
	assert.Equal(t, 3, len(report.GetScanAttempts()))
	assert.NotNil(t, data)
	assert.Equal(t, "None", data.Alg)
	assert.True(t, report.Issues[0].HasFailed())
}
