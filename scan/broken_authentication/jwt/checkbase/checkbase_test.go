package checkbase

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToFindingResult_Vulnerable(t *testing.T) {
	r := harnessx.DataResult(checkbase.ProbeResult{Payload: "exploited-token", Vulnerable: true})

	result := toFindingResult(r)

	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	assert.Equal(t, "exploited-token", f.Parameter)
}

func TestToFindingResult_NotVulnerable(t *testing.T) {
	r := harnessx.DataResult(checkbase.ProbeResult{Vulnerable: false})

	result := toFindingResult(r)

	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestToFindingResult_Skipped(t *testing.T) {
	r := harnessx.Result{Skipped: true, SkipReason: "HMAC-only exploit"}

	result := toFindingResult(r)

	assert.True(t, result.Skipped)
	assert.Equal(t, "HMAC-only exploit", result.SkipReason)
}

func TestToFindingResult_Err(t *testing.T) {
	r := harnessx.Result{Err: assert.AnError}

	result := toFindingResult(r)

	assert.Equal(t, assert.AnError, result.Err)
}

// TestAdapt_RunResource_ProbeContextUnavailable_ReturnsErr guards Adapt's
// own error handling: a resource whose ProbeCtx wasn't built (here, the
// store never ran ProbeCtxCheck) must surface as an error from RunResource
// rather than panic on the target.Data type assertion every jwtop check
// relies on.
func TestAdapt_RunResource_ProbeContextUnavailable_ReturnsErr(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	result, err := Adapt(blanksecret.Check).RunResource(context.Background(), harnessx.Target{}, resource, harnessx.NewStaticResultStore())

	require.Error(t, err)
	assert.False(t, result.Skipped)
}

// TestAdapt_DependsOn_KeepsJWTopDeps guards that Adapt keeps jwtop's own
// DependsOn (e.g. blank_secret depends on baseline) exactly as jwtop wrote
// it, in addition to ProbeCtxCheckID — losing it would run checks out of
// jwtop's own intended order.
func TestAdapt_DependsOn_KeepsJWTopDeps(t *testing.T) {
	adapted := Adapt(blanksecret.Check)

	assert.Contains(t, adapted.DependsOn, ProbeCtxCheckID)
	for _, dep := range blanksecret.Check.DependsOn {
		assert.Contains(t, adapted.DependsOn, dep)
	}
}

func TestBuildProbeCtx_MissingOperation(t *testing.T) {
	resource := harnessx.Resource{ID: "no-op"}

	_, err := buildProbeCtx(resource)

	require.Error(t, err)
}

func TestBuildProbeCtx(t *testing.T) {
	token := "header.payload.signature"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	pctx, err := buildProbeCtx(resource)

	require.NoError(t, err)
	assert.Equal(t, token, pctx.TokenString)
}

// TestProbeCtxCheck_RunResource_SharedViaStore guards the replacement for
// the old hand-rolled probeCtxCache: every check reading
// store.GetForResource(ProbeCtxCheckID, resourceID) must see the exact
// same *checkbase.ProbeCtx instance for a resource, since baseline mutates
// it in place and dependent checks read those mutations back off the same
// pointer.
func TestProbeCtxCheck_RunResource_SharedViaStore(t *testing.T) {
	token := "header.payload.signature"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	result, err := ProbeCtxCheck.RunResource(context.Background(), harnessx.Target{}, resource, harnessx.NewStaticResultStore())
	require.NoError(t, err)

	first, ok := harnessx.DataAs[*checkbase.ProbeCtx](result)
	require.True(t, ok)
	first.Alg = "HS256" // simulate baseline mutating the shared ProbeCtx

	store := harnessx.NewStaticResultStore(harnessx.Result{CheckID: ProbeCtxCheckID, ResourceID: resource.ID, Data: first})

	innerTarget, err := innerTargetFor(resource, store)
	require.NoError(t, err)

	second, ok := innerTarget.Data.(*checkbase.ProbeCtx)
	require.True(t, ok)
	assert.Same(t, first, second)
	assert.Equal(t, "HS256", second.Alg)
}
