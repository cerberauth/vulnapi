package httpheadersframeoptionsmissing_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
	httpheadersframeoptionsmissing "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_frame_options_missing"
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
	return httpheadersframeoptionsmissing.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, store)
}

func TestHTTPHeadersFrameOptionsMissing_Passed(t *testing.T) {
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

func TestHTTPHeadersFrameOptionsMissing_Failed(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	header := getValidHTTPHeaders()
	header.Del(httpheadersfetch.XFrameOptionsHTTPHeader)
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	store := headersStoreFor(t, op)
	result, err := runCheck(op, store)

	require.NoError(t, err)
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	assert.Equal(t, httpheadersfetch.XFrameOptionsHTTPHeader, f.Parameter)
}
