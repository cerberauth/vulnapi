package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const PasswordFlow OAuthFlow = "password"

func withHTTPClient(ctx context.Context, client *http.Client) context.Context {
	if client == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func oauth2Credential(token *oauth2.Token) Credential {
	return Credential{Value: token.AccessToken, Expiry: token.Expiry}
}

func NewOAuth2ClientCredentialsSource(tokenURL, clientID, clientSecret string, scopes []string, client *http.Client) CredentialSource {
	config := clientcredentials.Config{ClientID: clientID, ClientSecret: clientSecret, TokenURL: tokenURL, Scopes: scopes}
	return CredentialSourceFunc(func(ctx context.Context) (Credential, error) {
		token, err := config.Token(withHTTPClient(ctx, client))
		if err != nil {
			return Credential{}, fmt.Errorf("oauth2 client credentials: %w", redactOAuth2Error(err))
		}
		return oauth2Credential(token), nil
	})
}

func NewOAuth2PasswordSource(tokenURL, clientID, clientSecret, username, password string, scopes []string, client *http.Client) CredentialSource {
	config := oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, Endpoint: oauth2.Endpoint{TokenURL: tokenURL}, Scopes: scopes}
	return CredentialSourceFunc(func(ctx context.Context) (Credential, error) {
		token, err := config.PasswordCredentialsToken(withHTTPClient(ctx, client), username, password)
		if err != nil {
			return Credential{}, fmt.Errorf("oauth2 password: %w", redactOAuth2Error(err))
		}
		return oauth2Credential(token), nil
	})
}

func redactOAuth2Error(err error) error {
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) && retrieveErr.Response != nil {
		if retrieveErr.ErrorCode != "" {
			return fmt.Errorf("token endpoint returned HTTP %d: %s", retrieveErr.Response.StatusCode, retrieveErr.ErrorCode)
		}
		return fmt.Errorf("token endpoint returned HTTP %d", retrieveErr.Response.StatusCode)
	}
	return err
}

func NewCommandSource(command string) CredentialSource {
	return CredentialSourceFunc(func(ctx context.Context) (Credential, error) {
		var stdout bytes.Buffer
		cmd := exec.CommandContext(ctx, "sh", "-c", command) //nolint:gosec
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			return Credential{}, fmt.Errorf("login command: %w", err)
		}
		return Credential{Value: strings.TrimSpace(stdout.String())}, nil
	})
}

func NewHTTPLoginSource(url, data, tokenField string, client *http.Client) CredentialSource {
	if client == nil {
		client = http.DefaultClient
	}
	if tokenField == "" {
		tokenField = "access_token"
	}
	return CredentialSourceFunc(func(ctx context.Context) (Credential, error) {
		method := http.MethodGet
		var body io.Reader
		if data != "" {
			method = http.MethodPost
			body = strings.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, body)
		if err != nil {
			return Credential{}, fmt.Errorf("login request: %w", err)
		}
		if data != "" {
			contentType := "application/x-www-form-urlencoded"
			if json.Valid([]byte(data)) {
				contentType = "application/json"
			}
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return Credential{}, fmt.Errorf("login request: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return Credential{}, fmt.Errorf("login request returned HTTP %d", resp.StatusCode)
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
			return Credential{}, fmt.Errorf("login response is not JSON: %w", err)
		}
		token, ok := lookupField(payload, tokenField).(string)
		if !ok || token == "" {
			return Credential{}, fmt.Errorf("login response has no %q field", tokenField)
		}
		credential := Credential{Value: token}
		if expiresIn, ok := lookupField(payload, "expires_in").(float64); ok && expiresIn > 0 {
			credential.Expiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
		}
		return credential, nil
	})
}

func lookupField(payload map[string]interface{}, path string) interface{} {
	var current interface{} = payload
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}
