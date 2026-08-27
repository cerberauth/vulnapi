package httpmethodoverrideauthbypass

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	httpmethodoverride "github.com/cerberauth/vulnapi/scan/misconfiguration/http_method_override"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_method_override_auth_bypass", checkYAML)

func operationOf(resource harnessx.Resource) (*operation.Operation, bool) {
	return harnessx.ResourceDataAs[*operation.Operation](resource)
}

func winningOperationOf(store harnessx.ResultStore, resourceID string) (*operation.Operation, bool) {
	res, ok := store.GetForResource(httpmethodoverride.Check.ID, resourceID)
	if !ok {
		return nil, false
	}
	f, ok := harnessx.DataAs[*finding.Finding](res)
	if !ok || f == nil {
		return nil, false
	}
	op, ok := f.Data.(*operation.Operation)
	return op, ok
}

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
	_, ok := operationOf(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_method_override_auth_bypass: resource missing *operation.Operation")}, nil
	}

	winningOperation, ok := winningOperationOf(store, resource.ID)
	if !ok {
		return harnessx.Result{Err: errors.New("http_method_override_auth_bypass: missing method-override result from dependency")}, nil
	}

	attempt, err := finding.Fetch(ctx, winningOperation, auth.MustNewNoAuthSecurityScheme())
	if err != nil {
		return harnessx.Result{}, err
	}
	if finding.IsUnauthorizedStatusCodeOrSimilar(attempt.Response) {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Data: &finding.Finding{
		Attempt: attempt,
	}}, nil
},
	hxcheckdef.WithSkip(harnessx.SkipResourceWhen(func(_ context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) string {
		op, ok := operationOf(resource)
		if !ok {
			return "resource is missing operation data"
		}
		if op.GetSecurityScheme().GetType() == auth.None {
			return "operation has no authentication to bypass"
		}
		if _, ok := winningOperationOf(store, resource.ID); !ok {
			return "no HTTP method override was found to bypass authentication with"
		}
		return ""
	})),
)
