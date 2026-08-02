package introspectionenabled

import (
	"context"
	_ "embed"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("introspection_enabled", checkYAML)

const graphqlQuery = `query{__schema{queryType{name}}}`

func newPostGraphqlIntrospectionRequest(ctx context.Context, endpoint url.URL) (*http.Request, error) {
	payload := strings.NewReader("{\"query\":\"" + graphqlQuery + "\"}")
	return probe.NewRequest(ctx, http.MethodPost, endpoint.String(), payload, probe.WithHeader("Content-Type", "application/json"))
}

func newGetGraphqlIntrospectionRequest(ctx context.Context, endpoint url.URL) (*http.Request, error) {
	values := url.Values{}
	values.Add("query", graphqlQuery)
	endpoint.RawQuery = values.Encode()

	return probe.NewRequest(ctx, http.MethodGet, endpoint.String(), nil, probe.WithHeader("Content-Type", "application/json"))
}

func introspectionSucceeded(attempt *finding.Attempt) bool {
	return attempt.Response.GetStatusCode() == http.StatusOK && strings.Contains(attempt.Response.GetBody().String(), "queryType")
}

var Check = hxcheckdef.NewCheck(Def, func(ctx context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	resources := store.Resources()
	if len(resources) == 0 {
		return harnessx.Result{Skipped: true, SkipReason: "no resources"}, nil
	}
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resources[0])
	if !ok {
		return harnessx.Result{Err: errors.New("introspection_enabled: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()
	securitySchemes := []*auth.SecurityScheme{securityScheme}

	newRequest, err := newPostGraphqlIntrospectionRequest(ctx, op.URL)
	if err != nil {
		return harnessx.Result{}, err
	}
	newOperation, err := operation.NewOperationFromHTTPRequest(newRequest)
	if err != nil {
		return harnessx.Result{}, err
	}

	newOperation.SetSecuritySchemes(securitySchemes)
	attempt, err := finding.Fetch(ctx, newOperation, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}

	if introspectionSucceeded(attempt) {
		return harnessx.Result{Data: &finding.Finding{Operation: op, Attempt: attempt}}, nil
	}

	newRequest, err = newGetGraphqlIntrospectionRequest(ctx, op.URL)
	if err != nil {
		return harnessx.Result{}, err
	}
	newOperation, err = operation.NewOperationFromHTTPRequest(newRequest)
	if err != nil {
		return harnessx.Result{}, err
	}

	newOperation.SetSecuritySchemes(securitySchemes)
	attempt, err = finding.Fetch(ctx, newOperation, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}

	if introspectionSucceeded(attempt) {
		return harnessx.Result{Data: &finding.Finding{Operation: op, Attempt: attempt}}, nil
	}

	return harnessx.Result{}, nil
})
