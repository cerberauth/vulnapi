package fingerprint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	fingerprint "github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resourceStore struct{ resources []harnessx.Resource }

func (s *resourceStore) Get(_ harnessx.CheckID) (harnessx.Result, bool)                     { return harnessx.Result{}, false }
func (s *resourceStore) GetForResource(_ harnessx.CheckID, _ string) (harnessx.Result, bool) { return harnessx.Result{}, false }
func (s *resourceStore) Observations() []harnessx.Observation                               { return nil }
func (s *resourceStore) Resources() []harnessx.Resource                                     { return s.resources }

func runFingerprintCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	store := &resourceStore{resources: []harnessx.Resource{resource}}
	return fingerprint.Check.Run(context.Background(), harnessx.Target{URL: op.URL.String()}, store)
}

func fingerprintDataOf(t *testing.T, result harnessx.Result) fingerprint.FingerPrintData {
	t.Helper()
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	data, ok := f.Data.(fingerprint.FingerPrintData)
	require.True(t, ok)
	return data
}

func TestCheckSignatureHeader_Failed_WithServerSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.Servers))
	assert.Equal(t, data.Servers[0].Name, "Apache HTTP Server:2.4.29")
}

func TestCheckSignatureHeader_Failed_WithOSSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"Server": []string{"Ubuntu"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.OS))
	assert.Equal(t, data.OS[0].Name, "Ubuntu")
}

func TestCheckSignatureHeader_Failed_WithHostingSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"platform": []string{"hostinger"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.Hosting))
	assert.Equal(t, data.Hosting[0].Name, "Hostinger")
}

func TestCheckSignatureHeader_Failed_WithAuthenticationSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-auth0-requestid": []string{"id"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.AuthServices))
	assert.Equal(t, data.AuthServices[0].Name, "Auth0")
}

func TestCheckSignatureHeader_Failed_WithCDNSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"cf-cache-status": []string{"HIT"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.CDNs))
	assert.Equal(t, data.CDNs[0].Name, "Cloudflare")
}

func TestCheckSignatureHeader_Failed_WithLanguageSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-powered-by": []string{"PHP 7.4.3"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.Languages))
	assert.Equal(t, data.Languages[0].Name, "PHP")
}

func TestCheckSignatureHeader_Failed_WithFrameworkSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-powered-by": []string{"express"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 1, len(data.Languages))
	assert.Equal(t, data.Languages[0].Name, "Node.js")
	assert.Equal(t, 1, len(data.Frameworks))
	assert.Equal(t, data.Frameworks[0].Name, "Express")
}

func TestCheckSignatureHeader_Passed_WithoutDuplicate(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil).HeaderAdd(http.Header{"x-powered-by": []string{"next.js"}}))

	result, err := runFingerprintCheck(op)
	require.NoError(t, err)
	data := fingerprintDataOf(t, result)

	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	assert.Equal(t, 2, len(data.Frameworks))
}

func TestCheckSignatureHeader_Passed_WithoutSignatureHeader(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	result, err := runFingerprintCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}
