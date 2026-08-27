package acceptunauthenticated_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	acceptunauthenticated "github.com/cerberauth/vulnapi/scan/discover/accept_unauthenticated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runAcceptUnauthenticatedCheck(op *operation.Operation) (harnessx.Result, error) {
	resource := harnessx.Resource{ID: op.ID, URL: op.URL.String(), Method: op.Method, Data: op}
	return acceptunauthenticated.Check.RunResource(context.Background(), harnessx.Target{URL: op.URL.String()}, resource, nil)
}

func TestAcceptUnauthenticatedScanHandler_Failed_WhenNoAuthSecurityScheme(t *testing.T) {
	securityScheme := auth.MustNewNoAuthSecurityScheme()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})

	result, err := runAcceptUnauthenticatedCheck(op)

	assert.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.True(t, ok)
}

func TestCheckNoAuthOperationScanHandler_Passed_WhenAuthConfigured(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	securityScheme := auth.MustNewAuthorizationBearerSecurityScheme("default", &token)
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	op.SetSecuritySchemes([]*auth.SecurityScheme{securityScheme})

	result, err := runAcceptUnauthenticatedCheck(op)

	require.NoError(t, err)
	_, ok := harnessx.DataAs[*finding.Finding](result)
	assert.False(t, ok)
}
