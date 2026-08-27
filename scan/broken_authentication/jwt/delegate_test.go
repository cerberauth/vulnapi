package jwt

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
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runDelegatedCheck(jc harnessx.Check, op *operation.Operation, store harnessx.ResultStore) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return newDelegatedCheck(jc, blanksecret.Def).RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, store)
}

func TestNewDelegatedCheck_Vulnerable(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	token := "header.payload.signature"
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})

	loaderResults := map[harnessx.CheckID]harnessx.Result{
		blanksecret.Check.ID: {CheckID: blanksecret.Check.ID, Data: checkbase.ProbeResult{Payload: "exploited-token", Vulnerable: true}},
	}
	store := harnessx.NewStaticResultStore(harnessx.Result{CheckID: jwtProbeCheckID, Data: loaderResults})

	result, err := runDelegatedCheck(blanksecret.Check, op, store)

	require.NoError(t, err)
	f, ok := harnessx.DataAs[*finding.Finding](result)
	require.True(t, ok)
	assert.Equal(t, "exploited-token", f.Parameter)
}

func TestNewDelegatedCheck_NotVulnerable(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	token := "header.payload.signature"
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})

	loaderResults := map[harnessx.CheckID]harnessx.Result{
		blanksecret.Check.ID: {CheckID: blanksecret.Check.ID, Data: checkbase.ProbeResult{Vulnerable: false}},
	}
	store := harnessx.NewStaticResultStore(harnessx.Result{CheckID: jwtProbeCheckID, Data: loaderResults})

	result, err := runDelegatedCheck(blanksecret.Check, op, store)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}

func TestNewDelegatedCheck_JWTopSkipped(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	token := "header.payload.signature"
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})

	loaderResults := map[harnessx.CheckID]harnessx.Result{
		blanksecret.Check.ID: {CheckID: blanksecret.Check.ID, Skipped: true, SkipReason: "HMAC-only exploit"},
	}
	store := harnessx.NewStaticResultStore(harnessx.Result{CheckID: jwtProbeCheckID, Data: loaderResults})

	result, err := runDelegatedCheck(blanksecret.Check, op, store)

	require.NoError(t, err)
	assert.True(t, result.Skipped)
	assert.Equal(t, "HMAC-only exploit", result.SkipReason)
}

func TestNewDelegatedCheck_ProbeDidNotRun(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	token := "header.payload.signature"
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &token)})

	result, err := runDelegatedCheck(blanksecret.Check, op, harnessx.NewStaticResultStore())

	require.NoError(t, err)
	assert.True(t, result.Skipped)
}

func TestWithJWTChecks_RegistersChecksNotInLegacyLinkTable(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	s, err := scan.NewScan(operation.Operations{op}, &scan.ScanOptions{})
	require.NoError(t, err)

	WithJWTChecks(s)

	var ids []string
	for _, os := range s.GetOperationsScans() {
		ids = append(ids, os.CheckID)
	}
	assert.Contains(t, ids, "hmacconfusion")
	assert.Contains(t, ids, "jwkinjection")
	assert.Contains(t, ids, "psychicsig")
	assert.NotContains(t, ids, string(checkbase.CheckIDBaseline))
}

func TestWithJWTChecks_LegacyExcludeScansStillExcludesRenamedCheck(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	s, err := scan.NewScan(operation.Operations{op}, &scan.ScanOptions{
		ExcludeScans: []string{"jwt.blank_secret"},
	})
	require.NoError(t, err)

	WithJWTChecks(s)

	for _, os := range s.GetOperationsScans() {
		assert.NotEqual(t, string(blanksecret.Check.ID), os.CheckID)
	}
}
