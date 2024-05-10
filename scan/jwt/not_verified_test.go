package jwt_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan/jwt"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestNotVerifiedScanHandlerWithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.Nil(t, report)
}

func TestNotVerifiedScanHandlerWithoutJWT(t *testing.T) {
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", nil)
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.Nil(t, report)
}

func TestNotVerifiedScanHandler(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusOK, nil),
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
		}, t.Log),
	)
	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.False(t, report.HasFailedVulnerabilityReport())
}

func TestNotVerifiedScanHandlerWithNotVerifiedJWT(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusOK, nil),
			httpmock.NewBytesResponse(http.StatusOK, nil),
		}, t.Log),
	)
	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.HasFailedVulnerabilityReport())
}

func TestNotVerifiedScanHandlerWhenHTTPCodeIs401(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
			httpmock.NewBytesResponse(http.StatusUnauthorized, nil),
		}, t.Log),
	)
	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasFailedVulnerabilityReport())
}
