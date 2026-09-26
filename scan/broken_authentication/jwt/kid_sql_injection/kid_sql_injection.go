// Package kidsqlinjection adapts jwtop's kid_sql_injection crack check as
// a vulnapi check.
package kidsqlinjection

import (
	"context"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/vulnapi/scan"
	vulnjwtcheckbase "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = vulnjwtcheckbase.WithLink(kidsqlinjection.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection?utm_source=vulnapi-report")

// kidSQLTableCandidates lists table names tried, in order, for the
// kid_sql_injection check's payload until one yields a vulnerable result.
// The vulnerable table name is server-specific and can't be discovered by
// the check itself. A future PR will make this configurable via a config
// file; for now this covers common naming schemes.
var kidSQLTableCandidates = []string{
	exploit.DefaultKidSQLTable,
	"keys",
	"jwt_keys",
	"api_keys",
	"secrets",
	"users",
}

func probeResultOf(r harnessx.Result) (checkbase.ProbeResult, bool) {
	if pr, ok := harnessx.DataAs[checkbase.ProbeResult](r); ok {
		return pr, true
	}
	return checkbase.ResolveVariantResult(r.Attempts)
}

// withTableRetries wraps jwtop's kid_sql_injection Run to retry with each
// of kidSQLTableCandidates in turn, mutating the shared pctx.KidSQLTable
// field jwtop's own check reads its payload from: the payload only works
// when it names the server's actual table, which vulnapi can't know ahead
// of time, so it keeps trying candidates until one reports vulnerable or
// they're exhausted. Safe to mutate pctx here since KidSQLTable is read by
// no other jwtop check.
func withTableRetries(run harnessx.CheckFunc) harnessx.CheckFunc {
	return func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		pctx := target.Data.(*checkbase.ProbeCtx)

		result, err := run(ctx, target, store)
		if err != nil {
			return result, err
		}
		if pr, ok := probeResultOf(result); ok && pr.Vulnerable {
			return result, nil
		}

		for _, table := range kidSQLTableCandidates[1:] {
			pctx.KidSQLTable = table
			retryResult, retryErr := run(ctx, target, store)
			if retryErr != nil {
				continue
			}
			result = retryResult
			if pr, ok := probeResultOf(result); ok && pr.Vulnerable {
				break
			}
		}
		return result, nil
	}
}

var Check = vulnjwtcheckbase.Adapt(kidsqlinjection.Check, vulnjwtcheckbase.WithRunWrapper(withTableRetries))

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.kid_injection", "kid_sql_injection")
}
