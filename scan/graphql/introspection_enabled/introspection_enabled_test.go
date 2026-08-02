package introspectionenabled_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	introspectionenabled "github.com/cerberauth/vulnapi/scan/graphql/introspection_enabled"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resourceStore struct{ resources []harnessx.Resource }

func (s *resourceStore) Get(_ harnessx.CheckID) (harnessx.Result, bool)                     { return harnessx.Result{}, false }
func (s *resourceStore) GetForResource(_ harnessx.CheckID, _ string) (harnessx.Result, bool) { return harnessx.Result{}, false }
func (s *resourceStore) Observations() []harnessx.Observation                               { return nil }
func (s *resourceStore) Resources() []harnessx.Resource                                     { return s.resources }

func runIntrospectionEnabledCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	store := &resourceStore{resources: []harnessx.Resource{resource}}
	return introspectionenabled.Check.Run(context.Background(), harnessx.Target{URL: op.URL.String()}, store)
}

func TestGraphqlIntrospectionScanHandler_Failed_WhenRespondHTTPStatusIsOK(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	resBody := []byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`)
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, resBody))
	httpmock.RegisterResponder(http.MethodGet, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, resBody))

	result, err := runIntrospectionEnabledCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 1, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}

func TestGraphqlIntrospectionScanHandler_Failed_WhenRespond_GETMethodOnly_HTTPStatusIsOK(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	resBody := []byte(`{"data": {"__schema": {"queryType": {"name": "Query"}}}}`)
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusBadRequest, nil))
	httpmock.RegisterResponder(http.MethodGet, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, resBody))

	result, err := runIntrospectionEnabledCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}

func TestGraphqlIntrospectionScanHandler_Passed_WhenBadRequestStatus(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusBadRequest, nil))
	httpmock.RegisterResponder(http.MethodGet, op.URL.String(), httpmock.NewBytesResponder(http.StatusBadRequest, nil))

	result, err := runIntrospectionEnabledCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestGraphqlIntrospectionScanHandler_Passed_WhenOKStatusButNoQuery(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(http.MethodPost, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterResponder(http.MethodGet, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))

	result, err := runIntrospectionEnabledCheck(op)

	require.NoError(t, err)
	assert.Equal(t, 2, httpmock.GetTotalCallCount())
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}
