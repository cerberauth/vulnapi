package scenario

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithAllCommonScans_JWTChecksOnOptionalSecurity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "user"}).SignedString([]byte("a-long-and-random-secret-value"))
	require.NoError(t, err)

	tests := []struct {
		name            string
		optional        bool
		wantJWTFindings bool
	}{
		{name: "required security", optional: false, wantJWTFindings: true},
		{name: "optional security", optional: true, wantJWTFindings: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := operation.MustNewOperation(http.MethodGet, server.URL+"/status", nil, nil)
			schemes := []*auth.SecurityScheme{auth.MustNewAuthorizationBearerSecurityScheme("bearerAuth", &token)}
			if tt.optional {
				schemes = append(schemes, auth.MustNewNoAuthSecurityScheme())
			}
			op.SetSecuritySchemes(schemes)
			s, err := scan.NewScan(harnessx.New(), operation.Operations{op}, &scan.ScanOptions{IncludeScans: []string{"jwt.*"}})
			require.NoError(t, err)
			WithAllCommonScans(s)

			report, _, err := s.Execute(t.Context(), nil)
			require.NoError(t, err)

			var jwtFindings []string
			for _, f := range report.Findings {
				jwtFindings = append(jwtFindings, f.ID)
			}
			assert.Equal(t, tt.wantJWTFindings, len(jwtFindings) > 0, jwtFindings)
		})
	}
}
