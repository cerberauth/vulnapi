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

func TestBlankSecretScanHandlerWithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	report, err := jwt.BlankSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.Nil(t, report)
}

func TestBlankSecretScanHandlerWithoutJWT(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", nil)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := jwt.BlankSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}

func TestBlankSecretScanHandler(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation := request.NewOperation("http://localhost:8080/", "GET", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := jwt.BlankSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}
