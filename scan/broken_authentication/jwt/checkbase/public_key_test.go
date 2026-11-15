package checkbase

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func jwksServer(t *testing.T, key *rsa.PublicKey, path string) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/api/users")
	return u
}

func rs256Token(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	tok := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, jwtlib.MapClaims{"sub": "1"})
	tok.Header["kid"] = "k1"
	token, err := tok.SignedString(key)
	require.NoError(t, err)
	return token
}

func pemOf(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestResolvePublicKeyPEM_FromWellKnownJWKS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	operationURL := jwksServer(t, &key.PublicKey, "/.well-known/jwks.json")
	token := rs256Token(t, key)

	got := resolvePublicKeyPEM(operationURL, auth.MustNewAuthorizationBearerSecurityScheme("bearer", &token), token)

	assert.Equal(t, pemOf(t, &key.PublicKey), got)
}

func TestResolvePublicKeyPEM_FromOpenIDConnectJWKSURI(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksURL := jwksServer(t, &key.PublicKey, "/keys")
	token := rs256Token(t, key)
	securityScheme, err := auth.NewOpenIDConnectSecurityScheme("oidc", auth.NewOAuthValue(token, nil, nil, nil), &auth.OpenIDConnectConfig{JWKSURL: jwksURL.Scheme + "://" + jwksURL.Host + "/keys"})
	require.NoError(t, err)

	got := resolvePublicKeyPEM(&url.URL{}, securityScheme, token)

	assert.Equal(t, pemOf(t, &key.PublicKey), got)
}

func TestResolvePublicKeyPEM_KnownKeyWins(t *testing.T) {
	t.Cleanup(func() { SetPublicKeyPEM(nil) })
	SetPublicKeyPEM([]byte("known"))

	assert.Equal(t, []byte("known"), resolvePublicKeyPEM(&url.URL{}, auth.MustNewNoAuthSecurityScheme(), "token"))
}

func TestResolvePublicKeyPEM_SkipsHMACTokens(t *testing.T) {
	token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, jwtlib.MapClaims{"sub": "1"}).SignedString([]byte("secret"))
	require.NoError(t, err)
	fetchJWKS = func(string) (jwtlib.Keyfunc, error) {
		t.Fatal("JWKS must not be fetched for an HMAC token")
		return nil, nil
	}
	t.Cleanup(func() { fetchJWKS = defaultFetchJWKS })

	assert.Nil(t, resolvePublicKeyPEM(&url.URL{Scheme: "http", Host: "localhost"}, auth.MustNewNoAuthSecurityScheme(), token))
}
