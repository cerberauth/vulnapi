package fingerprint_test

import (
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckSignatureHeader_Failed_WithServerSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29"}}))

	report, err := fingerprint.ScanHandler(op, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.Servers))
	assert.Equal(t, data.Servers[0].Name, "Apache HTTP Server:2.4.29")
}

func TestCheckSignatureHeader_Failed_WithOSSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"Server": []string{"Ubuntu"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.OS))
	assert.Equal(t, data.OS[0].Name, "Ubuntu")
}

func TestCheckSignatureHeader_Failed_WithHostingSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"platform": []string{"hostinger"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.Hosting))
	assert.Equal(t, data.Hosting[0].Name, "Hostinger")
}

func TestCheckSignatureHeader_Failed_WithAuthenticationSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-auth0-requestid": []string{"id"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.AuthServices))
	assert.Equal(t, data.AuthServices[0].Name, "Auth0")
}

func TestCheckSignatureHeader_Failed_WithCDNSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"cf-cache-status": []string{"HIT"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.CDNs))
	assert.Equal(t, data.CDNs[0].Name, "Cloudflare")
}

func TestCheckSignatureHeader_Failed_WithLanguageSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-powered-by": []string{"PHP 7.4.3"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.Languages))
	assert.Equal(t, data.Languages[0].Name, "PHP")
}

func TestCheckSignatureHeader_Failed_WithFrameworkSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-powered-by": []string{"express"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 1, len(data.Languages))
	assert.Equal(t, data.Languages[0].Name, "Node.js")
	assert.Equal(t, 1, len(data.Frameworks))
	assert.Equal(t, data.Frameworks[0].Name, "Express")
}

func TestCheckSignatureHeader_Passed_WithoutDuplicate(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	securityScheme := auth.NewNoAuthSecurityScheme()
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)

	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-powered-by": []string{"next.js"}}))

	report, err := fingerprint.ScanHandler(operation, securityScheme)
	data, _ := report.GetData().(fingerprint.FingerPrintData)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasFailed())
	assert.Equal(t, 2, len(data.Frameworks))
}

func TestCheckSignatureHeader_Passed_WithoutSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	securityScheme := auth.NewAuthorizationBearerSecurityScheme("default", &token)
	operation := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	httpmock.RegisterResponder(operation.Method, operation.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	report, err := fingerprint.ScanHandler(operation, securityScheme)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.True(t, report.Issues[0].HasPassed())
}
