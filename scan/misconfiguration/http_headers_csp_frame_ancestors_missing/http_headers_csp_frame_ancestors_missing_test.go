package httpheaderscspframeancestorsmissing_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpheaderscspframeancestorsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_csp_frame_ancestors_missing"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getValidHTTPHeaders() http.Header {
	header := http.Header{}
	header.Add(httpheadersfetch.CSPHTTPHeader, "frame-ancestors 'none'")
	header.Add(httpheadersfetch.CORSOriginHTTPHeader, "http://localhost:8080")
	header.Add(httpheadersfetch.HSTSHTTPHeader, "max-age=63072000; includeSubDomains; preload")
	header.Add(httpheadersfetch.XContentTypeOptionsHTTPHeader, "nosniff")
	header.Add(httpheadersfetch.XFrameOptionsHTTPHeader, "DENY")
	return header
}

func headersStoreFor(t *testing.T, op *operation.Operation) harnessx.ResultStore {
	t.Helper()
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	result, err := httpheadersfetch.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
	require.NoError(t, err)
	result.CheckID = httpheadersfetch.Check.ID
	result.ResourceID = op.ID
	return harnessx.NewStaticResultStore(result)
}

func runCheck(op *operation.Operation, store harnessx.ResultStore) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return httpheaderscspframeancestorsmissing.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, store)
}

func TestCheckCSPFrameAncestors(t *testing.T) {
	assert.True(t, httpheaderscspframeancestorsmissing.CheckCSPFrameAncestors("default-src 'self'; frame-ancestors 'none'"))
	assert.False(t, httpheaderscspframeancestorsmissing.CheckCSPFrameAncestors("default-src 'self'; frame-ancestors http://example.com"))
	assert.False(t, httpheaderscspframeancestorsmissing.CheckCSPFrameAncestors(""))
}

func TestHTTPHeadersCSPFrameAncestorsMissing_Passed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(getValidHTTPHeaders()))

	store := headersStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestHTTPHeadersCSPFrameAncestorsMissing_FailedWhenCSPMissing(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	header := getValidHTTPHeaders()
	header.Del(httpheadersfetch.CSPHTTPHeader)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	store := headersStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}

func TestHTTPHeadersCSPFrameAncestorsMissing_FailedWhenDirectiveMissing(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	header := getValidHTTPHeaders()
	header.Set(httpheadersfetch.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'")
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	store := headersStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}

func TestHTTPHeadersCSPFrameAncestorsMissing_FailedWhenNotNone(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	header := getValidHTTPHeaders()
	header.Set(httpheadersfetch.CSPHTTPHeader, "default-src 'self' http://example.com; connect-src 'none'; frame-ancestors 'http://example.com'")
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	store := headersStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}
