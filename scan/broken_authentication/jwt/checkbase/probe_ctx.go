// Package checkbase embeds jwtop's check pack as vulnapi ScopePerResource
// checks, one run per JWT-bearing resource, building the pack context from
// each resource's operation.
package checkbase

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/jwtop/jwt/fuzz"
	"github.com/cerberauth/vulnapi/internal/auth"
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

type Options struct {
	HMACSecret         string
	OtherAudienceToken string
	OtherIssuerToken   string
	MaxTokenLifetime   time.Duration
}

var options Options

func SetOptions(o Options) {
	options = o
}

// SetKnownHMACSecret records a known JWT HMAC secret. buildProbeCtx seeds it
// as ProbeCtx.CrackedHMACSecret so checks that need a genuinely valid
// signature to reach a handler that verifies it (e.g. fuzz) can re-sign
// mutated tokens even when the weak_secret check can't crack the secret.
func SetKnownHMACSecret(secret string) {
	options.HMACSecret = secret
}

func tokenLocation(securityScheme *auth.SecurityScheme) checkbase.TokenLocation {
	if securityScheme.GetType() != auth.ApiKey || securityScheme.GetIn() == nil {
		return checkbase.DefaultTokenLocation()
	}
	switch *securityScheme.GetIn() {
	case auth.InHeader:
		return checkbase.TokenLocation{In: checkbase.TokenLocationHeader, Name: securityScheme.GetName()}
	case auth.InCookie:
		return checkbase.TokenLocation{In: checkbase.TokenLocationCookie, Name: securityScheme.GetName()}
	case auth.InQuery:
		return checkbase.TokenLocation{In: checkbase.TokenLocationQuery, Name: securityScheme.GetName()}
	}
	return checkbase.DefaultTokenLocation()
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
		Probe:            probe.New(probe.WithTransport(op.Transport), probe.WithTimeout(op.Timeout), probe.WithUserAgent(op.UserAgent()), probe.WithNoRedirects()),
		Candidates:       exploit.WeakSecrets(),
		TokenLocation:    tokenLocation(securityScheme),
		KidSQLTables:     KidSQLTableCandidates,
		FuzzEnabled:      true,
		FuzzMaxStringLen: fuzz.DefaultMaxStringLen,

		CrackedHMACSecret:  options.HMACSecret,
		PublicKeyPEM:       resolvePublicKeyPEM(&op.URL, securityScheme, tokenString),
		OtherAudienceToken: options.OtherAudienceToken,
		OtherIssuerToken:   options.OtherIssuerToken,
		MaxTokenLifetime:   options.MaxTokenLifetime,
		NewRequest: func(ctx context.Context, _ string) (*http.Request, error) {
			return op.NewHTTPRequest(ctx)
		},
	}, nil
}
