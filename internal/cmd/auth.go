package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cerberauth/vulnapi/config"
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

type authSource struct {
	cmd  *cobra.Command
	file *config.Auth
	err  error
}

func (a *authSource) secret(flag, env string, ref *config.SecretRef, field string) string {
	if value := stringFlagOrEnv(a.cmd, flag, env); value != "" || ref == nil || a.err != nil {
		return value
	}
	value, err := ref.Resolve(a.cmd.Context())
	if err != nil {
		a.err = fmt.Errorf("auth.%s: %w", field, err)
	}
	return value
}

func (a *authSource) string(flag string, fileValue string) string {
	if value, _ := a.cmd.Flags().GetString(flag); value != "" && (a.cmd.Flags().Changed(flag) || fileValue == "") {
		return value
	}
	return fileValue
}

// ApplyAuthFlags builds the credentials of the scan from the auth flags,
// their environment variables, and the auth section of the configuration
// file, in that order of precedence.
func ApplyAuthFlags(cmd *cobra.Command, client *request.Client, settings *ScanSettings) (*auth.CredentialRegistry, error) {
	source := &authSource{cmd: cmd, file: &config.Auth{}}
	if settings != nil && settings.Config != nil && settings.Config.Auth != nil {
		source.file = settings.Config.Auth
	}
	file := source.file
	login := file.Login
	if login == nil || cmd.Flags().Changed("login-command") || cmd.Flags().Changed("login-url") {
		login = &config.Login{}
	}

	scopes, _ := cmd.Flags().GetStringArray("oauth2-scope")
	if !cmd.Flags().Changed("oauth2-scope") && len(file.Scopes) > 0 {
		scopes = file.Scopes
	}
	tokenURL := source.string("token-url", file.TokenURL)
	loginCommand := source.string("login-command", login.Command)
	loginURL := source.string("login-url", login.URL)
	loginTokenField := source.string("login-token-field", login.TokenField)
	loginData, _ := cmd.Flags().GetString("login-data")
	if loginData == "" && login.Data != nil && loginURL == login.URL {
		loginData = source.secret("login-data", "", login.Data, "login.data")
	}

	options := auth.CredentialOptions{
		ClientID:        source.secret("client-id", ClientIDEnv, file.ClientID, "clientId"),
		ClientSecret:    source.secret("client-secret", ClientSecretEnv, file.ClientSecret, "clientSecret"),
		TokenURL:        tokenURL,
		Scopes:          scopes,
		Username:        source.secret("oauth2-username", OAuth2UsernameEnv, file.Username, "username"),
		Password:        source.secret("oauth2-password", OAuth2PasswordEnv, file.Password, "password"),
		LoginCommand:    loginCommand,
		LoginURL:        loginURL,
		LoginData:       loginData,
		LoginTokenField: loginTokenField,
		HTTPClient:      &http.Client{Transport: client.Transport, Timeout: client.Timeout},
	}
	if source.err != nil {
		return nil, source.err
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

	if location := source.string("jwt-public-key", file.JWTPublicKey); location != "" {
		publicKeyPEM, err := readKey(location)
		if err != nil {
			return nil, fmt.Errorf("reading --jwt-public-key: %w", err)
		}
		jwtcheckbase.SetPublicKeyPEM(publicKeyPEM)
	}
	return registry, nil
}
