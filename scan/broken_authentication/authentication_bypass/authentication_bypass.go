package authenticationbypass

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/checkutil"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/scan"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("authentication_bypass", checkYAML)

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	op, ok := checkutil.Operation(resource)
	if !ok {
		return harnessx.Result{Err: errors.New("authentication_bypass: resource missing *operation.Operation")}, nil
	}

	var baseline *finding.Response
	if op.GetSecurityScheme().HasValidValue() {
		if baselineAttempt, err := finding.FetchWithoutRedirect(ctx, op, nil); err == nil {
			baseline = baselineAttempt.Response
		}
	}

	attempt, err := finding.FetchWithoutRedirect(ctx, op, auth.MustNewNoAuthSecurityScheme())
	if err != nil {
		return harnessx.Result{}, err
	}
	if finding.IsRejected(attempt.Response, baseline) {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Data: &finding.Finding{
		Attempt: attempt,
	}}, nil
},
	hxcheckdef.WithSkip(harnessx.SkipResourceWhen(func(_ context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) string {
		op, ok := checkutil.Operation(resource)
		if !ok {
			return "resource is missing operation data"
		}
		if op.GetSecurityScheme().GetType() == auth.None {
			return "operation has no authentication to bypass"
		}
		if op.AcceptsUnauthenticated() {
			return "operation declares an optional security requirement"
		}
		return ""
	})),
)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "broken_authentication.authentication_bypass")
}
