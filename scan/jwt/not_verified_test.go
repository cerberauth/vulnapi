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

func TestNotVerifiedScanHandlerWithoutJwt(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(405, nil))

	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestNotVerifiedScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(200, nil),
			httpmock.NewBytesResponse(401, nil),
		}, t.Log),
	)
	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestNotVerifiedScanHandlerWithNotVerifiedJWT(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(200, nil),
			httpmock.NewBytesResponse(200, nil),
		}, t.Log),
	)
	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestNotVerifiedScanHandlerWhenHTTPCodeIs401(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.ResponderFromMultipleResponses(
		[]*http.Response{
			httpmock.NewBytesResponse(401, nil),
			httpmock.NewBytesResponse(401, nil),
		}, t.Log),
	)
	report, err := jwt.NotVerifiedScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}
