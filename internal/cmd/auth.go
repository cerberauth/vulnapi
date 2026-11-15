package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	jwtcheckbase "github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
	"github.com/spf13/cobra"
)

const (
	ClientIDEnv       = "VULNAPI_CLIENT_ID"
	ClientSecretEnv   = "VULNAPI_CLIENT_SECRET" //nolint:gosec
	OAuth2UsernameEnv = "VULNAPI_OAUTH2_USERNAME"
	OAuth2PasswordEnv = "VULNAPI_OAUTH2_PASSWORD" //nolint:gosec
)

func AddAuthFlags(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.String("client-id", "", "OAuth2 client ID used to obtain an access token (env "+ClientIDEnv+")")
	flags.String("client-secret", "", "OAuth2 client secret used to obtain an access token (env "+ClientSecretEnv+")")
	flags.String("token-url", "", "OAuth2 token endpoint, overriding the one of the security scheme")
	flags.StringArray("oauth2-scope", nil, "OAuth2 scope to request (repeatable)")
	flags.String("oauth2-username", "", "Resource owner username for the OAuth2 password flow (env "+OAuth2UsernameEnv+")")
	flags.String("oauth2-password", "", "Resource owner password for the OAuth2 password flow (env "+OAuth2PasswordEnv+")")
	flags.String("login-command", "", "Command printing the token to use on stdout, run before the scan and when the token expires")
	flags.String("login-url", "", "URL called to obtain the token to use, before the scan and when the token expires")
	flags.String("login-data", "", "Body sent to --login-url (JSON or form encoded); the request is a GET when empty")
	flags.String("login-token-field", "access_token", "Field of the --login-url JSON response holding the token (dot separated path)")
	flags.String("jwt-public-key", "", "Path or URL to the PEM public key of the JWT under test (defaults to the key of /.well-known/jwks.json)")
}

func stringFlagOrEnv(cmd *cobra.Command, name, env string) string {
	if value, _ := cmd.Flags().GetString(name); value != "" {
		return value
	}
	return os.Getenv(env)
}

func readKey(location string) ([]byte, error) {
	if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
		return os.ReadFile(location) //nolint:gosec
	}
	resp, err := http.Get(location) //nolint:gosec,noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func ApplyAuthFlags(cmd *cobra.Command, client *request.Client) (*auth.CredentialRegistry, error) {
	scopes, _ := cmd.Flags().GetStringArray("oauth2-scope")
	tokenURL, _ := cmd.Flags().GetString("token-url")
	loginCommand, _ := cmd.Flags().GetString("login-command")
	loginURL, _ := cmd.Flags().GetString("login-url")
	loginData, _ := cmd.Flags().GetString("login-data")
	loginTokenField, _ := cmd.Flags().GetString("login-token-field")

	options := auth.CredentialOptions{
		ClientID:        stringFlagOrEnv(cmd, "client-id", ClientIDEnv),
		ClientSecret:    stringFlagOrEnv(cmd, "client-secret", ClientSecretEnv),
		TokenURL:        tokenURL,
		Scopes:          scopes,
		Username:        stringFlagOrEnv(cmd, "oauth2-username", OAuth2UsernameEnv),
		Password:        stringFlagOrEnv(cmd, "oauth2-password", OAuth2PasswordEnv),
		LoginCommand:    loginCommand,
		LoginURL:        loginURL,
		LoginData:       loginData,
		LoginTokenField: loginTokenField,
		HTTPClient:      &http.Client{Transport: client.Transport, Timeout: client.Timeout},
	}
	if loginCommand != "" && loginURL != "" {
		return nil, fmt.Errorf("use either --login-command or --login-url, not both")
	}
	if options.ClientID == "" && (options.ClientSecret != "" || options.Username != "") {
		return nil, fmt.Errorf("--client-id is required for the OAuth2 flows")
	}

	registry := auth.NewCredentialRegistry(options)
	client.Credentials = registry
	client.Transport = registry.Transport(client.Transport)

	if location, _ := cmd.Flags().GetString("jwt-public-key"); location != "" {
		publicKeyPEM, err := readKey(location)
		if err != nil {
			return nil, fmt.Errorf("reading --jwt-public-key: %w", err)
		}
		jwtcheckbase.SetPublicKeyPEM(publicKeyPEM)
	}
	return registry, nil
}
