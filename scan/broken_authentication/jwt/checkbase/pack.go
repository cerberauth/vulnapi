package checkbase

import (
	"context"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/harnessx/embed"
	"github.com/cerberauth/jwtop/jwt/crack"
	jwtopcheckbase "github.com/cerberauth/jwtop/jwt/crack/checkbase"
)

// packIDs are the jwtop checks vulnapi runs; their dependencies come along.
var packIDs = []harnessx.CheckID{
	"jwt.no_verification",
	"jwt.alg_none",
	"jwt.blank_secret",
	"jwt.null_signature",
	"jwt.hmac_confusion",
	"jwt.psychic_signature",
	"jwt.kid_sql_injection",
	"jwt.kid_path_traversal",
	"jwt.jwk_injection",
	"jwt.jku_injection",
	"jwt.x5c_injection",
	"jwt.x5u_injection",
	"jwt.weak_secret",
	"jwt.timestamp_tampering",
	"jwt.fuzz",
	"jwt.missing_expiry",
	"jwt.long_lifetime",
	"jwt.expired_accepted",
	"jwt.audience_not_validated",
	"jwt.issuer_not_validated",
	"jwt.claim_removal",
	"jwt.scope_not_validated",
}

var checks = func() []harnessx.Check {
	pack, err := embed.Select(crack.Checks(), packIDs...)
	if err != nil {
		panic(err)
	}
	return embed.MustChecks(pack, embed.Options{
		Scope:     harnessx.ScopePerResource,
		ContextID: ProbeCtxCheckID,
		Skip:      SkipUnlessJWT(),
		Context: func(_ context.Context, _ harnessx.Target, resource *harnessx.Resource) (any, error) {
			return buildProbeCtx(*resource)
		},
	})
}()

// Checks returns the embedded jwtop checks, with the internal context and
// baseline checks first.
func Checks() []harnessx.Check {
	return append([]harnessx.Check(nil), checks...)
}

// Check returns the embedded jwtop check with id.
func Check(id harnessx.CheckID) harnessx.Check {
	for _, c := range checks {
		if c.ID == id {
			return c
		}
	}
	panic("jwt: no embedded check " + string(id))
}

// ProbeCtxCheck builds the pack context of each JWT-bearing resource.
var ProbeCtxCheck = Check(ProbeCtxCheckID)

// BaselineCheck captures the baseline response of each JWT-bearing resource.
var BaselineCheck = Check(jwtopcheckbase.CheckIDBaseline)

// WithLink returns a copy of def with Link overridden, for the checks that
// have a vulnapi-specific advisory page.
func WithLink(def checkdef.CheckDef, link string) checkdef.CheckDef {
	def.Link = link
	return def
}
