package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Resolve returns the credential value: the referenced secret, or an access
// token obtained with the OAuth2 client credentials grant, or the password
// grant when username and password are set. defaultTokenURL is used when
// the configuration sets no tokenUrl.
func (c Credential) Resolve(ctx context.Context, client *http.Client, defaultTokenURL string) (string, error) {
	if c.OAuth2 == nil {
		return c.SecretRef.Resolve(ctx)
	}
	return c.OAuth2.token(ctx, client, defaultTokenURL)
}

func resolveOptional(ctx context.Context, ref *SecretRef) (string, error) {
	if ref == nil {
		return "", nil
	}
	return ref.Resolve(ctx)
}

func (o *OAuth2) token(ctx context.Context, client *http.Client, defaultTokenURL string) (string, error) {
	tokenURL := o.TokenURL
	if tokenURL == "" {
		tokenURL = defaultTokenURL
	}
	if tokenURL == "" {
		return "", errors.New("oauth2: tokenUrl is required when the security scheme declares no token URL")
	}
	values := make([]string, 4)
	for i, ref := range []*SecretRef{o.ClientID, o.ClientSecret, o.Username, o.Password} {
		value, err := resolveOptional(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("oauth2: %w", err)
		}
		values[i] = value
	}
	clientID, clientSecret, username, password := values[0], values[1], values[2], values[3]

	if client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	var token *oauth2.Token
	var err error
	if o.Username != nil {
		config := oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: oauth2.Endpoint{TokenURL: tokenURL}, Scopes: o.Scopes}
		token, err = config.PasswordCredentialsToken(ctx, username, password)
	} else {
		config := clientcredentials.Config{ClientID: clientID, ClientSecret: clientSecret, TokenURL: tokenURL, Scopes: o.Scopes}
		token, err = config.Token(ctx)
	}
	if err != nil {
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr.Response != nil {
			return "", fmt.Errorf("oauth2: token endpoint returned HTTP %d", retrieveErr.Response.StatusCode)
		}
		return "", fmt.Errorf("oauth2: %w", err)
	}
	return token.AccessToken, nil
}
