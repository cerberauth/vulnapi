package checkbase

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
	"strings"
	"sync"

	jwtop "github.com/cerberauth/jwtop/jwt"
	"github.com/cerberauth/jwtop/jwt/editor"
	"github.com/cerberauth/vulnapi/internal/auth"
	jwtlib "github.com/golang-jwt/jwt/v5"
)

var knownPublicKeyPEM []byte

func SetPublicKeyPEM(publicKeyPEM []byte) {
	knownPublicKeyPEM = publicKeyPEM
}

var jwksCache sync.Map

var defaultFetchJWKS = jwtop.FetchJWKS

var fetchJWKS = defaultFetchJWKS

func jwksURLs(operationURL *url.URL, securityScheme *auth.SecurityScheme) []string {
	var urls []string
	if config, ok := securityScheme.GetConfig().(*auth.OpenIDConnectConfig); ok && config.JWKSURL != "" {
		urls = append(urls, config.JWKSURL)
	}
	if operationURL != nil && operationURL.Host != "" {
		urls = append(urls, (&url.URL{Scheme: operationURL.Scheme, Host: operationURL.Host, Path: "/.well-known/jwks.json"}).String())
	}
	return urls
}

func keyfuncFor(jwksURL string) jwtlib.Keyfunc {
	if cached, ok := jwksCache.Load(jwksURL); ok {
		keyfunc, _ := cached.(jwtlib.Keyfunc)
		return keyfunc
	}
	keyfunc, err := fetchJWKS(jwksURL)
	if err != nil {
		keyfunc = nil
	}
	jwksCache.Store(jwksURL, keyfunc)
	return keyfunc
}

func resolvePublicKeyPEM(operationURL *url.URL, securityScheme *auth.SecurityScheme, token string) []byte {
	if len(knownPublicKeyPEM) > 0 {
		return knownPublicKeyPEM
	}
	te, err := editor.NewTokenEditor(token)
	if err != nil {
		return nil
	}
	alg := te.GetToken().Method.Alg()
	if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") && !strings.HasPrefix(alg, "ES") {
		return nil
	}
	for _, jwksURL := range jwksURLs(operationURL, securityScheme) {
		keyfunc := keyfuncFor(jwksURL)
		if keyfunc == nil {
			continue
		}
		key, err := keyfunc(te.GetToken())
		if err != nil {
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			continue
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	return nil
}
