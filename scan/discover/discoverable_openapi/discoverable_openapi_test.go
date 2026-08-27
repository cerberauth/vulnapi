package discoverableopenapi_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resourceStore struct{ resources []harnessx.Resource }

func (s *resourceStore) Get(_ harnessx.CheckID) (harnessx.Result, bool)                     { return harnessx.Result{}, false }
func (s *resourceStore) GetForResource(_ harnessx.CheckID, _ string) (harnessx.Result, bool) { return harnessx.Result{}, false }
func (s *resourceStore) Observations() []harnessx.Observation                               { return nil }
func (s *resourceStore) Resources() []harnessx.Resource                                     { return s.resources }

func runDiscoverableOpenAPICheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	store := &resourceStore{resources: []harnessx.Resource{resource}}
	return discoverableopenapi.Check.Run(context.Background(), harnessx.Target{URL: op.URL.String()}, store)
}

func TestDiscoverableScanner_Passed_WhenNoDiscoverableGraphqlPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil).HeaderAdd(http.Header{"Server": []string{"Apache/2.4.29 (Ubuntu)"}}))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	result, err := runDiscoverableOpenAPICheck(op)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 10)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestDiscoverableScanner_Failed_WhenOneOpenAPIFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/swagger/v1/swagger.json", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	result, err := runDiscoverableOpenAPICheck(op)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}
