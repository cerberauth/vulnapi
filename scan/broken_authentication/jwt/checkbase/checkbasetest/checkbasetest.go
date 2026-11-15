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

const Secret = "secret"

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

func Run(t *testing.T, check harnessx.Check, op *operation.Operation, options checkbase.Options) (*finding.Finding, string) {
	t.Helper()
	checkbase.SetOptions(options)
	t.Cleanup(func() { checkbase.SetOptions(checkbase.Options{}) })

	ctx := context.Background()
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	var results []harnessx.Result
	for _, dep := range []harnessx.Check{checkbase.ProbeCtxCheck, checkbase.BaselineCheck} {
		result, err := dep.RunResource(ctx, harnessx.Target{}, resource, harnessx.NewStaticResultStore(results...))
		require.NoError(t, err)
		result.CheckID = dep.ID
		result.ResourceID = resource.ID
		results = append(results, result)
	}
	store := harnessx.NewStaticResultStore(results...)

	if reason := check.Skip.EvalResource(ctx, harnessx.Target{}, resource, store); reason != "" {
		return nil, reason
	}
	result, err := check.RunResource(ctx, harnessx.Target{}, resource, store)
	require.NoError(t, err)
	require.NoError(t, result.Err)
	f, _ := harnessx.DataAs[*finding.Finding](result)
	return f, ""
}
