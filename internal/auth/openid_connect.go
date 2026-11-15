package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type OpenIDConnectConfig struct {
	URL      string
	TokenURL string
	JWKSURL  string
}

func NewOpenIDConnectSecurityScheme(name string, value *OAuthValue, config *OpenIDConnectConfig) (*SecurityScheme, error) {
	return newOAuthBasedSecurityScheme(name, OpenIdConnect, nil, value, config)
}

type OpenIDConfiguration struct {
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

func DiscoverOpenIDConfiguration(ctx context.Context, client *http.Client, url string) (*OpenIDConfiguration, error) {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching openid configuration: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openid configuration returned HTTP %d", resp.StatusCode)
	}
	var configuration OpenIDConfiguration
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&configuration); err != nil {
		return nil, fmt.Errorf("decoding openid configuration: %w", err)
	}
	return &configuration, nil
}
