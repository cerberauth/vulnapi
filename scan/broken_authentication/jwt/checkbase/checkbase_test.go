package checkbase

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
)

func jwtResource(t *testing.T, url string) harnessx.Resource {
	t.Helper()
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "u"}).SignedString([]byte("secret"))
	require.NoError(t, err)
	op := operation.MustNewOperation(http.MethodGet, url, nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})
	return harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
}

func TestChecks_EmbedJWTopPack(t *testing.T) {
	checks := Checks()
	require.NotEmpty(t, checks)
	assert.Equal(t, ProbeCtxCheckID, checks[0].ID)
	assert.True(t, ProbeCtxCheck.Internal)
	assert.True(t, BaselineCheck.Internal)

	adapted := Check(blanksecret.Check.ID)
	assert.Equal(t, harnessx.ScopePerResource, adapted.Scope)
	assert.Contains(t, adapted.DependsOn, ProbeCtxCheckID)
	for _, dep := range blanksecret.Check.DependsOn {
		assert.Contains(t, adapted.DependsOn, dep)
	}
	assert.Panics(t, func() { Check("jwt.unknown") })
}

func TestChecks_RunPerJWTResource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	withJWT := jwtResource(t, srv.URL+"/jwt")
	withJWT.ID = "jwt"
	plain := operation.MustNewOperation(http.MethodGet, srv.URL+"/plain", nil, nil)
	discover := harnessx.Check{ID: "_operations", Run: func(context.Context, harnessx.Target, harnessx.ResultStore) (harnessx.Result, error) {
		return harnessx.Result{Resources: []harnessx.Resource{withJWT, {ID: "plain", URL: plain.URL.String(), Data: plain}}}, nil
	}}

	checks := []harnessx.Check{discover}
	for _, c := range Checks() {
		c.DependsOn = append([]harnessx.CheckID{discover.ID}, c.DependsOn...)
		checks = append(checks, c)
	}
	summary, err := harnessx.New(harnessx.WithChecks(checks...)).Run(context.Background(), harnessx.Target{URL: srv.URL})
	require.NoError(t, err)

	var noVerification []harnessx.Result
	for _, r := range summary.Results {
		assert.NotEqual(t, checkbase.CheckIDBaseline, r.CheckID)
		assert.NotEqual(t, ProbeCtxCheckID, r.CheckID)
		if r.CheckID == "jwt.no_verification" {
			noVerification = append(noVerification, r)
		}
	}
	require.Len(t, noVerification, 2)
	for _, r := range noVerification {
		if r.ResourceID == withJWT.ID {
			assert.NotEmpty(t, r.Observations)
		} else {
			assert.Equal(t, "security scheme is not a JWT bearer token", r.SkipReason)
		}
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

func TestBuildProbeCtx_DoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	}))
	defer srv.Close()
	token := "header.payload.signature"
	op := operation.MustNewOperation(http.MethodGet, srv.URL+"/account", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	pctx, err := buildProbeCtx(resource)
	require.NoError(t, err)
	req, err := pctx.NewRequest(context.Background(), token)
	require.NoError(t, err)
	resp, err := pctx.Probe.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusFound, resp.StatusCode)
}
func TestProbeCtxCheck_RunResource_SeedsKnownHMACSecret(t *testing.T) {
	t.Cleanup(func() { SetKnownHMACSecret("") })

	token := "header.payload.signature"
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	run := func() *checkbase.ProbeCtx {
		result, err := ProbeCtxCheck.RunResource(context.Background(), harnessx.Target{}, resource, harnessx.NewStaticResultStore())
		require.NoError(t, err)
		pctx, ok := harnessx.DataAs[*checkbase.ProbeCtx](result)
		require.True(t, ok)
		return pctx
	}

	assert.Empty(t, run().CrackedHMACSecret)

	SetKnownHMACSecret("s3cr3t")
	assert.Equal(t, "s3cr3t", run().CrackedHMACSecret)
}
