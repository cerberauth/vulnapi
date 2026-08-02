package authenticationbypass

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("authentication_bypass", checkYAML)

func operationOf(resource harnessx.Resource) (*operation.Operation, bool) {
	return harnessx.ResourceDataAs[*operation.Operation](resource)
}

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	op, ok := operationOf(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("authentication_bypass: resource missing *operation.Operation")}, nil
	}

	noAuthSecurityScheme := auth.MustNewNoAuthSecurityScheme()
	attempt, err := finding.Fetch(ctx, op, noAuthSecurityScheme)
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
	hxcheckdef.WithSkip(harnessx.SkipResourceWhen(func(_ context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) string {
		op, ok := operationOf(resource)
		if !ok {
			return "resource is missing operation data"
		}
		if op.GetSecurityScheme().GetType() == auth.None {
			return "operation has no authentication to bypass"
		}
		return ""
	})),
)
