package scenario_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	jwtop "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runJWTChecks runs the JWT checks against a server that accepts the
// requests for which accept returns true and answers 401 otherwise, and
// returns the IDs of the reported findings.
func runJWTChecks(t *testing.T, token string, accept func(token string) bool) []string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || !accept(requestToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 1}`))
	}))
	defer server.Close()

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	client := request.NewClient(request.NewClientOptions{Header: header})
	u, _ := url.Parse(server.URL)
	s, err := scenario.NewURLScan(harnessx.New(), http.MethodGet, u, "", client, &scan.ScanOptions{
		IncludeScans: []string{"jwt"},
	})
	require.NoError(t, err)

	report, _, err := s.Execute(t.Context(), nil)
	require.NoError(t, err)

	var ids []string
	for _, f := range report.Findings {
		ids = append(ids, f.ID)
	}
	slices.Sort(ids)
	return ids
}

func TestJWTChecksAgainstServerAcceptingAnyToken(t *testing.T) {
	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte("a-long-and-unguessable-secret"))
	require.NoError(t, err)

	ids := runJWTChecks(t, token, func(string) bool { return true })

	// the other JWT checks are redundant once the signature is known not to
	// be verified
	assert.Equal(t, []string{"no_verification"}, ids)
}

func TestJWTChecksAgainstServerAcceptingAlgNone(t *testing.T) {
	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte("a-long-and-unguessable-secret"))
	require.NoError(t, err)

	ids := runJWTChecks(t, token, func(requestToken string) bool {
		if requestToken == token {
			return true
		}
		encodedHeader, _, _ := strings.Cut(requestToken, ".")
		rawHeader, err := base64.RawURLEncoding.DecodeString(encodedHeader)
		if err != nil {
			return false
		}
		var header struct {
			Alg string `json:"alg"`
		}
		return json.Unmarshal(rawHeader, &header) == nil && strings.EqualFold(header.Alg, "none")
	})

	assert.Equal(t, []string{"algnone"}, ids)
}

// verifyHS256 reports whether token is an HS256 JWT signed with secret.
func verifyHS256(token string, secret []byte) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(rawHeader, &header) != nil || header.Alg != "HS256" {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && hmac.Equal(signature, mac.Sum(nil))
}

func TestJWTChecksAgainstServerUsingWeakSecret(t *testing.T) {
	secret := []byte("secret")
	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, secret)
	require.NoError(t, err)

	ids := runJWTChecks(t, token, func(requestToken string) bool { return verifyHS256(requestToken, secret) })

	assert.Contains(t, ids, "secret")
}

func TestJWTChecksAgainstServerVerifyingAStrongSecret(t *testing.T) {
	secret := []byte("a-long-and-unguessable-secret")
	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, secret)
	require.NoError(t, err)

	ids := runJWTChecks(t, token, func(requestToken string) bool { return verifyHS256(requestToken, secret) })

	assert.Empty(t, ids)
}

func TestJWTChecksAgainstServerAcceptingOnlyTheValidToken(t *testing.T) {
	token, err := jwtop.CreateWithSecret(jwtop.CreateOptions{Algorithm: "HS256"}, []byte("a-long-and-unguessable-secret"))
	require.NoError(t, err)

	ids := runJWTChecks(t, token, func(requestToken string) bool { return requestToken == token })

	assert.Empty(t, ids)
}
