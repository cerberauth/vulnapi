package openapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	HttpSchemeType          string = "http"
	OAuth2SchemeType        string = "oauth2"
	OpenIdConnectSchemeType string = "openidconnect"
	ApiKeySchemeType        string = "apikey"

	BasicScheme  string = "basic"
	BearerScheme string = "bearer"
	// DigestScheme string = "digest"
	// OAuthScheme  string = "oauth"
	// PrivateToken string = "privateToken"

	// NoneScheme    string = "none"
	// UnknownScheme string = "unknown"
)

// ErrUnsupportedSecurityScheme is wrapped by the errors of security schemes
// vulnapi cannot use. SecuritySchemeMap skips those schemes.
var ErrUnsupportedSecurityScheme = errors.New("unsupported security scheme")

func NewErrUnsupportedScheme(scheme string) error {
	return fmt.Errorf("%w: unsupported scheme: %s", ErrUnsupportedSecurityScheme, scheme)
}

func NewErrUnsupportedSecuritySchemeType(schemeType string) error {
	return fmt.Errorf("%w: unsupported security scheme type: %s", ErrUnsupportedSecurityScheme, schemeType)
}

func mapHTTPSchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *string) (*auth.SecurityScheme, error) {
	switch schemeScheme := strings.ToLower(scheme.Value.Scheme); schemeScheme {
	case BearerScheme:
		securityScheme, err := auth.NewAuthorizationBearerSecurityScheme(name, securitySchemeValue)
		if err != nil {
			return nil, err
		}

		// bearerFormat is only a hint: formats other than JWT, such as
		// "opaque", are sent as plain bearer tokens
		if strings.EqualFold(scheme.Value.BearerFormat, "jwt") {
			if err := securityScheme.SetTokenFormat(auth.JWTTokenFormat); err != nil {
				return nil, err
			}
		}
		return securityScheme, nil
	case BasicScheme:
		var credentials *auth.HTTPBasicCredentials
		if securitySchemeValue != nil && *securitySchemeValue != "" {
			username, password, ok := strings.Cut(*securitySchemeValue, ":")
			if !ok {
				return nil, fmt.Errorf("security scheme %q expects a user:password value", name)
			}
			credentials = auth.NewHTTPBasicCredentials(username, password)
		}
		return auth.NewAuthorizationBasicSecurityScheme(name, credentials)
	default:
		return nil, NewErrUnsupportedScheme(schemeScheme)
	}
}

func mapAPIKeySchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *string) (*auth.SecurityScheme, error) {
	// The API key is sent under the header, query parameter or cookie name
	// the scheme declares, not under the scheme's own name.
	paramName := scheme.Value.Name
	if paramName == "" {
		paramName = name
	}
	return auth.NewAPIKeySecurityScheme(paramName, auth.SchemeIn(scheme.Value.In), securitySchemeValue)
}

func mapOAuth2SchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *auth.OAuthValue) (*auth.SecurityScheme, error) {
	if scheme.Value.Flows == nil {
		return auth.NewOAuthSecurityScheme(name, nil, securitySchemeValue, nil)
	}

	var cfg *auth.OAuthConfig
	switch {
	case scheme.Value.Flows.AuthorizationCode != nil:
		cfg = &auth.OAuthConfig{
			TokenURL:   scheme.Value.Flows.AuthorizationCode.TokenURL,
			RefreshURL: scheme.Value.Flows.AuthorizationCode.RefreshURL,
		}
	case scheme.Value.Flows.Implicit != nil:
		cfg = &auth.OAuthConfig{
			TokenURL:   scheme.Value.Flows.Implicit.TokenURL,
			RefreshURL: scheme.Value.Flows.Implicit.RefreshURL,
		}
	case scheme.Value.Flows.ClientCredentials != nil:
		cfg = &auth.OAuthConfig{
			TokenURL:   scheme.Value.Flows.ClientCredentials.TokenURL,
			RefreshURL: scheme.Value.Flows.ClientCredentials.RefreshURL,
		}
	case scheme.Value.Flows.Password != nil:
		cfg = &auth.OAuthConfig{
			TokenURL:   scheme.Value.Flows.Password.TokenURL,
			RefreshURL: scheme.Value.Flows.Password.RefreshURL,
		}
	}

	return auth.NewOAuthSecurityScheme(name, nil, securitySchemeValue, cfg)
}

func oauth2FlowCredential(scheme *openapi3.SecurityScheme, credentials *auth.CredentialRegistry) *auth.ManagedCredential {
	if scheme.Flows == nil {
		return nil
	}
	if flow := scheme.Flows.ClientCredentials; flow != nil {
		if credential := credentials.OAuth2(auth.ClientCredentials, flow.TokenURL); credential != nil {
			return credential
		}
	}
	if flow := scheme.Flows.Password; flow != nil {
		if credential := credentials.OAuth2(auth.PasswordFlow, flow.TokenURL); credential != nil {
			return credential
		}
	}
	return nil
}

func mapOpenIDConnectSchemeType(ctx context.Context, name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *auth.OAuthValue, credentials *auth.CredentialRegistry) (*auth.SecurityScheme, *auth.ManagedCredential, error) {
	config := &auth.OpenIDConnectConfig{URL: scheme.Value.OpenIdConnectUrl}
	var credential *auth.ManagedCredential
	options := credentials.Options()
	if config.URL != "" && (securitySchemeValue != nil || options.ClientID != "") {
		configuration, err := auth.DiscoverOpenIDConfiguration(ctx, options.HTTPClient, config.URL)
		if err == nil {
			config.TokenURL = configuration.TokenEndpoint
			config.JWKSURL = configuration.JWKSURI
		} else if options.ClientID != "" && options.TokenURL == "" {
			return nil, nil, fmt.Errorf("security scheme %q: %w", name, err)
		}
	}
	if securitySchemeValue == nil {
		if options.Username != "" {
			credential = credentials.OAuth2(auth.PasswordFlow, config.TokenURL)
		} else {
			credential = credentials.OAuth2(auth.ClientCredentials, config.TokenURL)
		}
	}
	securityScheme, err := auth.NewOpenIDConnectSecurityScheme(name, securitySchemeValue, config)
	return securityScheme, credential, err
}

func (openapi *OpenAPI) SecuritySchemeMap(ctx context.Context, values *SecuritySchemeValues) (auth.SecuritySchemesMap, error) {
	if openapi.Doc.Components == nil || openapi.Doc.Components.SecuritySchemes == nil {
		return nil, nil
	}

	var err error
	var securitySchemeValue interface{}

	securitySchemes := map[string]*auth.SecurityScheme{}
	for name, scheme := range openapi.Doc.Components.SecuritySchemes {
		securitySchemeValue = values.Get(name)

		var value *string
		if securitySchemeValue != nil {
			value, _ = securitySchemeValue.(*string)
		}

		schemeType := strings.ToLower(scheme.Value.Type)
		schemeLabel := schemeCounterLabel(schemeType, scheme.Value.Scheme, scheme.Value.In)
		formatLabel := bearerFormatLabel(schemeType, scheme.Value)

		var oauthValue *auth.OAuthValue
		if value != nil {
			oauthValue = auth.NewOAuthValue(*value, nil, nil, nil)
		}

		var credential *auth.ManagedCredential
		switch schemeType {
		case HttpSchemeType:
			securitySchemes[name], err = mapHTTPSchemeType(name, scheme, value)
		case OAuth2SchemeType:
			securitySchemes[name], err = mapOAuth2SchemeType(name, scheme, oauthValue)
			if value == nil {
				credential = oauth2FlowCredential(scheme.Value, values.Credentials)
			}
		case OpenIdConnectSchemeType:
			securitySchemes[name], credential, err = mapOpenIDConnectSchemeType(ctx, name, scheme, oauthValue, values.Credentials)
		case ApiKeySchemeType:
			securitySchemes[name], err = mapAPIKeySchemeType(name, scheme, value)
		default:
			err = NewErrUnsupportedSecuritySchemeType(schemeType)
		}

		if errors.Is(err, ErrUnsupportedSecurityScheme) {
			securitySchemesCounter.Add(ctx, 1, schemeLabel, formatLabel, supportedLabel(err))
			delete(securitySchemes, name)
			fmt.Fprintf(os.Stderr, "Warning: skipping security scheme %q: %v\n", name, err)
			continue
		}
		if err != nil {
			securitySchemesCounter.Add(ctx, 1, schemeLabel, formatLabel, supportedLabel(err))
			return nil, err
		}

		if credential == nil && !values.has(name) && securitySchemes[name].GetScheme() != auth.BasicScheme {
			credential = values.Credentials.Default()
		}
		if credential != nil {
			if err := securitySchemes[name].SetCredential(ctx, credential); err != nil {
				return nil, err
			}
		}

		securitySchemesCounter.Add(ctx, 1, schemeLabel, formatLabel, "yes")
	}

	return securitySchemes, nil
}

// securitySchemesCounter counts the security schemes of scanned specs, by
// scheme, bearer format and whether vulnapi supports it: "yes", "no" for a
// scheme it skips as unsupported and "error" for one it should handle but
// that is invalid (Argvio catalog).
var securitySchemesCounter = argvio.NewCounter("openapi.security-scheme", argvio.Dims("scheme", "format", "supported"))

// supportedLabel is the supported dimension of a scheme that failed to map:
// "no" for a scheme vulnapi can't scan, "error" for one it should handle but
// that is invalid.
func supportedLabel(err error) string {
	if errors.Is(err, ErrUnsupportedSecurityScheme) {
		return "no"
	}
	return "error"
}

// schemeCounterLabel names a security scheme for the Argvio counters from a
// fixed vocabulary, so nothing taken from the scanned spec is ever sent.
// schemeType is lower case; scheme and in are the spec's (or auth package's)
// values, of any case.
func schemeCounterLabel(schemeType, scheme string, in string) string {
	switch schemeType {
	case HttpSchemeType:
		return "http-" + telemetryx.Vocab(scheme, BearerScheme, BasicScheme)
	case ApiKeySchemeType:
		return "apikey-" + telemetryx.Vocab(in, "header", "query", "cookie")
	case OAuth2SchemeType, OpenIdConnectSchemeType:
		return schemeType
	default:
		return telemetryx.Vocab(schemeType, "mutualtls")
	}
}

// bearerFormatLabel is the bearer format of an http bearer scheme ("jwt",
// "other" for any other declared format), and "none" when there is no format
// to speak of.
func bearerFormatLabel(schemeType string, scheme *openapi3.SecurityScheme) string {
	if schemeType != HttpSchemeType || !strings.EqualFold(scheme.Scheme, BearerScheme) || scheme.BearerFormat == "" {
		return "none"
	}
	return telemetryx.Vocab(scheme.BearerFormat, "jwt")
}
