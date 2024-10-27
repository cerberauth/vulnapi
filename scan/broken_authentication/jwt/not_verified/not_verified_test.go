package notverified_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	notverified "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/not_verified"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotVerifiedScanHandler_WithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := notverified.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestNotVerifiedScanHandler_Passed_WhenNoJWTAndUnauthorizedResponse(t *testing.T) {
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", nil)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := notverified.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestNotVerifiedScanHandler_Failed_WhenUnauthorizedThenOK(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
			httpmock.NewBytesResponse(http.StatusOK, nil),
		}, t.Log),
	)
	report, err := notverified.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
}

func TestNotVerifiedScanHandler_Skipped_WhenOKFirstRequest(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusOK, nil),
			httpmock.NewBytesResponse(http.StatusOK, nil),
		}, t.Log),
	)
	report, err := notverified.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestNotVerifiedScanHandler_Failed_WhenUnauthorizedThenUnauthorized(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
		}, t.Log),
	)
	report, err := notverified.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasPassed())
}
