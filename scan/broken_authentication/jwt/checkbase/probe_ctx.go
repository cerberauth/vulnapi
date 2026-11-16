// Package checkbase embeds jwtop's check pack as vulnapi ScopePerResource
// checks, one run per JWT-bearing resource, building the pack context from
// each resource's operation.
package checkbase

import (
	"errors"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/jwtop/jwt/fuzz"
)

// ProbeCtxCheckID is the internal check building the *checkbase.ProbeCtx of
// each JWT-bearing resource, which every jwtop check depends on.
const ProbeCtxCheckID harnessx.CheckID = "jwt.probe_ctx"

// KidSQLTableCandidates lists the table names the kid_sql_injection check
// tries, in order, until one yields a vulnerable result. The vulnerable table
// name is server-specific and can't be discovered by the check itself, so
// this covers common naming schemes.
var KidSQLTableCandidates = []string{
	exploit.DefaultKidSQLTable,
	"keys",
	"jwt_keys",
	"api_keys",
	"secrets",
	"users",
}

// knownHMACSecret is the HMAC secret the user supplied (--jwt-secret), if any.
var knownHMACSecret string

// SetKnownHMACSecret records a known JWT HMAC secret. buildProbeCtx seeds it
// as ProbeCtx.CrackedHMACSecret so checks that need a genuinely valid
// signature to reach a handler that verifies it (e.g. fuzz) can re-sign
// mutated tokens even when the weak_secret check can't crack the secret.
func SetKnownHMACSecret(secret string) {
	knownHMACSecret = secret
}

// buildProbeCtx builds the *checkbase.ProbeCtx every directly-adapted
// jwtop check (see Adapt) reads and mutates as it runs — the same scratch
// state jwtop's own single-target ProbeAll builds before running its
// checks.
func buildProbeCtx(resource harnessx.Resource) (*checkbase.ProbeCtx, error) {
	op, ok := Operation(resource)
	if !ok {
		return nil, errors.New("jwt: resource missing *operation.Operation")
	}
	securityScheme := op.GetSecurityScheme()

	tokenString := securityScheme.GetToken()
	if !securityScheme.HasValidValue() {
		emptyEditor, err := editor.NewEmptyTokenEditor()
		if err != nil {
			return nil, err
		}
		tokenString = emptyEditor.GetToken().Raw
	}

	return &checkbase.ProbeCtx{
		TokenString:      tokenString,
		Probe:            probe.New(probe.WithTransport(op.Transport), probe.WithTimeout(op.Timeout), probe.WithUserAgent(op.UserAgent())),
		Candidates:       exploit.WeakSecrets(),
		TokenLocation:    checkbase.DefaultTokenLocation(),
		KidSQLTables:     KidSQLTableCandidates,
		FuzzEnabled:      true,
		FuzzMaxStringLen: fuzz.DefaultMaxStringLen,

		CrackedHMACSecret: knownHMACSecret,
		PublicKeyPEM:      resolvePublicKeyPEM(&op.URL, securityScheme, tokenString),
	}, nil
}
