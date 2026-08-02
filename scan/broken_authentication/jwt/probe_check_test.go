package jwt

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runJWTProbeCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return newJWTProbeCheck().RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, harnessx.NewStaticResultStore())
}

func TestNewJWTProbeCheck_Skip_NoSecurityScheme(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	reason := newJWTProbeCheck().Skip.EvalResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, harnessx.NewStaticResultStore())

	assert.NotEmpty(t, reason)
}

func TestNewJWTProbeCheck_Skip_NotJWT(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()})
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}

	reason := newJWTProbeCheck().Skip.EvalResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, harnessx.NewStaticResultStore())

	assert.NotEmpty(t, reason)
}

func TestNewJWTProbeCheck_DetectsBlankSecret(t *testing.T) {
	client := request.GetDefaultClient()
	httpmock.ActivateNonDefault(client.Client)
	defer httpmock.DeactivateAndReset()

	validToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "user"}).SignedString([]byte("a-real-not-guessable-secret"))
	require.NoError(t, err)
	blankSecretToken, err := exploit.BlankSecret(validToken)
	require.NoError(t, err)

	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, client)
	op.SetSecuritySchemes([]*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("Authorization", &validToken)})

	httpmock.RegisterResponder(http.MethodGet, op.URL.String(), func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") == "Bearer "+blankSecretToken {
			return httpmock.NewStringResponse(http.StatusOK, ""), nil
		}
		return httpmock.NewStringResponse(http.StatusUnauthorized, ""), nil
	})

	result, err := runJWTProbeCheck(op)
	require.NoError(t, err)

	results, ok := harnessx.DataAs[map[harnessx.CheckID]harnessx.Result](result)
	require.True(t, ok)

	blankSecretResult, ok := results[blanksecret.Check.ID]
	require.True(t, ok)
	pr, ok := harnessx.DataAs[checkbase.ProbeResult](blankSecretResult)
	require.True(t, ok)
	assert.True(t, pr.Vulnerable)
}
