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

func TestWeakHMACSecretScanHandlerWithoutSecurityScheme(t *testing.T) {
	securityScheme := auth.NewNoAuthSecurityScheme()
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	report, err := jwt.WeakHMACSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.Nil(t, report)
}

func TestWeakHMACSecretScanHandlerWithJWTUsingOtherAlg(t *testing.T) {
	token := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMxMjMifQ.vLBmArLmAKEshqJa3px6qYfrkAfiwBrKPs5dCMxqj9bdiEKR5W4o0Srxt6VHZKzsxIGMTTsqpW21lKnYsLw5DA"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	report, err := jwt.WeakHMACSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.Nil(t, report)
}

func TestWeakHMACSecretScanHandlerWithoutJWT(t *testing.T) {
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", nil)
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := jwt.WeakHMACSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.Nil(t, report)
}

func TestWeakHMACSecretScanHandlerWithWeakJWT(t *testing.T) {
	client := request.DefaultClient
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(client, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := jwt.WeakHMACSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.HasVulnerabilityReport())
}

func TestWeakHMACSecretScanHandlerWithStrongerJWT(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.MWUarT7Q4e5DqnZbdr7VKw3rx9VW-CrvoVkfpllS4CY"
	securityScheme, _ := auth.NewAuthorizationJWTBearerSecurityScheme("token", &token)
	operation, _ := request.NewOperation(request.DefaultClient, http.MethodGet, "http://localhost:8080/", nil, nil, nil)

	httpmock.RegisterResponder(operation.Method, operation.Request.URL.String(), httpmock.NewBytesResponder(http.StatusUnauthorized, nil))

	report, err := jwt.WeakHMACSecretScanHandler(operation, securityScheme)

	assert.NoError(t, err)
	assert.Equal(t, 0, httpmock.GetTotalCallCount())
	assert.False(t, report.HasVulnerabilityReport())
}
