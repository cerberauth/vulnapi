package checkbasetest

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// Secret signs the test tokens. It must stay out of jwtop's weak secrets dictionary,
// otherwise the weak_secret check cracks it and the checks that need the
// secret never see it as unknown.
const Secret = "vulnapi-test-signing-key-7f3a91"

func Sign(t *testing.T, claims jwtlib.MapClaims) string {
	t.Helper()
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims).SignedString([]byte(Secret))
	require.NoError(t, err)
	return token
}

type Request struct {
	Method string
	Body   string
}

func Server(t *testing.T, accept func(claims jwtlib.MapClaims) bool) (string, *[]Request) {
	t.Helper()
	var requests []Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests = append(requests, Request{Method: r.Method, Body: string(body)})
		claims := jwtlib.MapClaims{}
		_, err := jwtlib.ParseWithClaims(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), claims, func(*jwtlib.Token) (interface{}, error) {
			return []byte(Secret), nil
		}, jwtlib.WithoutClaimsValidation())
		if err != nil || r.Method != http.MethodPost || !accept(claims) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &requests
}

func Operation(t *testing.T, url string, token string) *operation.Operation {
	t.Helper()
	op := operation.MustNewOperation(http.MethodPost, url, nil, nil)
	op.Body = []byte(`{"name":"test"}`)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("bearer", &token)})
	return op
}

// Run runs check, with the checks it depends on, against op through the
// harnessx engine. It returns a finding when the check observed the
// vulnerability, or the reason the check was skipped.
func Run(t *testing.T, check harnessx.Check, op *operation.Operation, options checkbase.Options) (*finding.Finding, string) {
	t.Helper()
	checkbase.SetOptions(options)
	t.Cleanup(func() { checkbase.SetOptions(checkbase.Options{}) })

	resource := harnessx.Resource{ID: "jwt", URL: op.URL.String(), Method: op.Method, Data: op}
	discover := harnessx.Check{ID: "_operations", Run: func(context.Context, harnessx.Target, harnessx.ResultStore) (harnessx.Result, error) {
		return harnessx.Result{Resources: []harnessx.Resource{resource}}, nil
	}}

	byID := map[harnessx.CheckID]harnessx.Check{}
	for _, c := range checkbase.Checks() {
		byID[c.ID] = c
	}
	checks := []harnessx.Check{discover}
	seen := map[harnessx.CheckID]bool{}
	var add func(id harnessx.CheckID)
	add = func(id harnessx.CheckID) {
		c, ok := byID[id]
		if !ok || seen[id] {
			return
		}
		seen[id] = true
		for _, dep := range c.DependsOn {
			add(dep)
		}
		c.DependsOn = append([]harnessx.CheckID{discover.ID}, c.DependsOn...)
		checks = append(checks, c)
	}
	add(checkbase.ProbeCtxCheck.ID)
	add(checkbase.BaselineCheck.ID)
	add(check.ID)

	summary, err := harnessx.New(harnessx.WithChecks(checks...)).Run(context.Background(), harnessx.Target{URL: op.URL.String()})
	require.NoError(t, err)

	for _, r := range summary.Results {
		if r.CheckID != check.ID || r.ResourceID != resource.ID {
			continue
		}
		require.NoError(t, r.Err)
		if r.SkipReason != "" {
			return nil, r.SkipReason
		}
		if len(r.Observations) > 0 {
			return &finding.Finding{Parameter: r.Observations[0].Evidence}, ""
		}
	}
	return nil, ""
}
