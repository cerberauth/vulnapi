package jwt

import (
	"context"
	"errors"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/jwtcheck"
)

const jwtProbeCheckID harnessx.CheckID = "_jwt_probe"

func newJWTProbeCheck() harnessx.Check {
	return harnessx.Check{
		ID:    jwtProbeCheckID,
		Name:  "JWT Probe (jwtop)",
		Scope: harnessx.ScopePerResource,
		Skip:  jwtcheck.SkipUnlessJWT(),
		RunResource: func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
			op, ok := jwtcheck.Operation(resource)
			if !ok {
				return harnessx.Result{Err: errors.New("jwt: resource missing *operation.Operation")}, nil
			}
			securityScheme := op.GetSecurityScheme()

			tokenString := securityScheme.GetToken()
			if !securityScheme.HasValidValue() {
				emptyEditor, err := editor.NewEmptyTokenEditor()
				if err != nil {
					return harnessx.Result{}, err
				}
				tokenString = emptyEditor.GetToken().Raw
			}

			pctx := &checkbase.ProbeCtx{
				TokenString:   tokenString,
				Probe:         probe.New(probe.WithTransport(op.Transport), probe.WithTimeout(op.Timeout)),
				Candidates:    exploit.WeakSecrets(),
				TokenLocation: checkbase.DefaultTokenLocation(),
				KidSQLTable:   kidSQLTableCandidates[0],
			}

			checks, _ := crack.BuildChecks()
			engine := harnessx.New(harnessx.WithChecks(checks...))
			summary, err := engine.Run(ctx, harnessx.Target{URL: op.URL.String(), Data: pctx})
			if err != nil {
				return harnessx.Result{}, err
			}

			results := make(map[harnessx.CheckID]harnessx.Result, len(summary.Results))
			for _, r := range summary.Results {
				results[r.CheckID] = r
			}

			// The kid_sql_injection payload only works when it names the
			// server's actual table; retry with the remaining candidates
			// until one is vulnerable. Each retry reruns the full check set
			// (rather than a hand-picked subset) so it stays correct as
			// jwtop's check dependencies evolve.
			if kidResult, ok := results[kidsqlinjection.Check.ID]; ok {
				if pr, ok := probeResultOf(kidResult); !ok || !pr.Vulnerable {
					for _, table := range kidSQLTableCandidates[1:] {
						pctx.KidSQLTable = table
						retryEngine := harnessx.New(harnessx.WithChecks(checks...))
						retrySummary, err := retryEngine.Run(ctx, harnessx.Target{URL: op.URL.String(), Data: pctx})
						if err != nil {
							continue
						}
						for _, r := range retrySummary.Results {
							if r.CheckID == kidsqlinjection.Check.ID {
								results[kidsqlinjection.Check.ID] = r
							}
						}
						if pr, ok := probeResultOf(results[kidsqlinjection.Check.ID]); ok && pr.Vulnerable {
							break
						}
					}
				}
			}

			return harnessx.Result{Data: results}, nil
		},
	}
}
