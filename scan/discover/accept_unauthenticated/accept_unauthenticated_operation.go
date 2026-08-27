package acceptunauthenticated

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

var Def = hxcheckdef.MustParseCheckDefYAML("accept_unauthenticated", checkYAML)

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
	if !ok {
		return harnessx.Result{Err: errors.New("accept_unauthenticated: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()

	if securityScheme.GetType() != auth.None {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Data: &finding.Finding{}}, nil
})
