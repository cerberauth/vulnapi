package kidinjection_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	kidinjection "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/kid_injection"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKidInjectionScanHandler_WithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)

	report, err := kidinjection.ScanHandler(op, securityScheme)

	require.NoError(t, err)
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestKidInjectionScanHandler_Skipped_WhenNoJWT(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", nil)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := kidinjection.ScanHandler(op, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasBeenSkipped())
}

func TestKidInjectionScanHandler_Passed_WhenUnauthorizedResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := kidinjection.ScanHandler(op, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasPassed())
}

func TestKidInjectionScanHandler_Failed_WhenSQLInjectionOKResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := kidinjection.ScanHandler(op, securityScheme)
	data, _ := report.GetData().(*kidinjection.KidInjectionData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.NotNil(t, data)
	assert.Equal(t, kidinjection.KidInjectionTypeSQLInjection, data.Type)
	assert.True(t, report.Issues[0].HasFailed())
}

func TestKidInjectionScanHandler_Failed_WhenPathTraversalOKResponse(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("token", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
			httpmock.NewBytesResponse(http.StatusOK, nil),
		}, t.Log),
	)

	report, err := kidinjection.ScanHandler(op, securityScheme)
	data, _ := report.GetData().(*kidinjection.KidInjectionData)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.NotNil(t, data)
	assert.Equal(t, kidinjection.KidInjectionTypePathTraversal, data.Type)
	assert.True(t, report.Issues[0].HasFailed())
}
