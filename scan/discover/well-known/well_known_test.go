package wellknown_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	wellknown "github.com/cerberauth/vulnapi/scan/discover/well-known"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resourceStore struct{ resources []harnessx.Resource }

func (s *resourceStore) Get(_ harnessx.CheckID) (harnessx.Result, bool)                     { return harnessx.Result{}, false }
func (s *resourceStore) GetForResource(_ harnessx.CheckID, _ string) (harnessx.Result, bool) { return harnessx.Result{}, false }
func (s *resourceStore) Observations() []harnessx.Observation                               { return nil }
func (s *resourceStore) Resources() []harnessx.Resource                                     { return s.resources }

func runWellKnownCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	store := &resourceStore{resources: []harnessx.Resource{resource}}
	return wellknown.Check.Run(context.Background(), harnessx.Target{URL: op.URL.String()}, store)
}

func TestDiscoverableScanner_Passed_WhenNoDiscoverableWellKnownPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusNoContent, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	result, err := runWellKnownCheck(op)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 5)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestDiscoverableScanner_Failed_WhenOneWellKnownPathFound(t *testing.T) {
	client := request.NewClient(request.NewClientOptions{
		RateLimit: 500,
	})
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/.well-known/jwks.json", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	httpmock.RegisterResponder(op.Method, op.URL.String(), httpmock.NewBytesResponder(http.StatusOK, nil))
	httpmock.RegisterNoResponder(httpmock.NewBytesResponder(http.StatusNotFound, nil))

	result, err := runWellKnownCheck(op)

	require.NoError(t, err)
	assert.Greater(t, httpmock.GetTotalCallCount(), 0)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}
