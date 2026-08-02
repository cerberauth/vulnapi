package httptrack

import (
	"context"
	_ "embed"
	"errors"
	"net/http"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_track", checkYAML)

const TrackMethod = "TRACK"

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_track: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()

	newOperation, err := op.Clone()
	if err != nil {
		return harnessx.Result{}, err
	}
	newOperation.Method = TrackMethod

	attempt, err := finding.Fetch(ctx, newOperation, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}
	if attempt.Response.GetStatusCode() != http.StatusOK {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Data: &finding.Finding{
		Attempt: attempt,
	}}, nil
})
