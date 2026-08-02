package httpheadersfetch_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPHeadersFetch_FetchesOnce(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	token := "token"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("default", &token)})
	header := http.Header{}
	header.Add(httpheadersfetch.CSPHTTPHeader, "frame-ancestors 'none'")
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(header))

	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	result, err := httpheadersfetch.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())

	data, ok := harnessx.DataAs[*httpheadersfetch.FetchResult](result)
	require.True(t, ok)
	require.NotNil(t, data.Attempt)
	assert.Equal(t, "frame-ancestors 'none'", data.Attempt.Response.GetHeader().Get(httpheadersfetch.CSPHTTPHeader))
}
