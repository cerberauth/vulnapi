// Package checkbase adapts jwtop's ScopeGlobal JWT crack checks — written
// to scan exactly one target per engine run, reading their
// *checkbase.ProbeCtx from target.Data — into genuine vulnapi
// ScopePerResource checks, one per JWT-bearing resource, without
// reimplementing any check's own Run/RunVariant logic.
package checkbase

import (
	"context"
	"errors"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/jwtop/jwt/exploit"
)

// ProbeCtxCheckID is the CheckID every check directory's Adapt call
// depends on: the *checkbase.ProbeCtx built for a resource by
// ProbeCtxCheck, read back via store.GetForResource.
const ProbeCtxCheckID harnessx.CheckID = "jwt.probe_ctx"

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
		TokenString:   tokenString,
		Probe:         probe.New(probe.WithTransport(op.Transport), probe.WithTimeout(op.Timeout)),
		Candidates:    exploit.WeakSecrets(),
		TokenLocation: checkbase.DefaultTokenLocation(),
		KidSQLTable:   exploit.DefaultKidSQLTable,
	}, nil
}

// ProbeCtxCheck builds and caches, once per JWT-bearing resource, the
// *checkbase.ProbeCtx every other check in this package depends on and
// reads via store.GetForResource(ProbeCtxCheckID, resourceID) — the
// harnessx engine's own per-resource result caching stands in for what
// used to be a hand-rolled sync.Map cache. Registered with a nil
// checkdef.CheckDef, like scan/misconfiguration/http_cookies_fetch.Check:
// it's plumbing, never itself reportable.
var ProbeCtxCheck = harnessx.Check{
	ID:    ProbeCtxCheckID,
	Name:  "JWT Probe Context",
	Scope: harnessx.ScopePerResource,
	Skip:  SkipUnlessJWT(),
	RunResource: func(_ context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
		pctx, err := buildProbeCtx(resource)
		if err != nil {
			return harnessx.Result{}, err
		}
		return harnessx.Result{Data: pctx}, nil
	},
}

// innerTargetFor builds the single-target harnessx.Target (URL + this
// resource's *checkbase.ProbeCtx as Data) every check adapted by Adapt
// needs to run its unmodified Run/RunVariant/Skip logic for resource,
// exactly as jwtop's own ProbeAll would build it for a single-target
// scan.
func innerTargetFor(resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Target, error) {
	op, ok := Operation(resource)
	if !ok {
		return harnessx.Target{}, errors.New("jwt: resource missing *operation.Operation")
	}
	res, ok := store.GetForResource(ProbeCtxCheckID, resource.ID)
	if !ok {
		return harnessx.Target{}, errors.New("jwt probe context unavailable")
	}
	pctx, ok := harnessx.DataAs[*checkbase.ProbeCtx](res)
	if !ok {
		return harnessx.Target{}, errors.New("jwt probe context unavailable")
	}
	return harnessx.Target{URL: op.URL.String(), Data: pctx}, nil
}
