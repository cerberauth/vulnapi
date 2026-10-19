package openapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/x/telemetryx"
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

func NewErrUnsupportedBearerFormat(bearerFormat string) error {
	return fmt.Errorf("unsupported bearer format: %s", bearerFormat)
}

func NewErrUnsupportedScheme(scheme string) error {
	return fmt.Errorf("unsupported scheme: %s", scheme)
}

func NewErrUnsupportedSecuritySchemeType(schemeType string) error {
	return fmt.Errorf("unsupported security scheme type: %s", schemeType)
}

func mapHTTPSchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *string) (*auth.SecurityScheme, error) {
	switch schemeScheme := strings.ToLower(scheme.Value.Scheme); schemeScheme {
	case BearerScheme:
		securityScheme, err := auth.NewAuthorizationBearerSecurityScheme(name, securitySchemeValue)
		if err != nil {
			return nil, err
		}

		switch bearerFormat := strings.ToLower(scheme.Value.BearerFormat); bearerFormat {
		case "":
			return securityScheme, nil
		case "jwt":
			err := securityScheme.SetTokenFormat(auth.JWTTokenFormat)
			if err != nil {
				return nil, err
			}
			return securityScheme, nil
		default:
			return nil, NewErrUnsupportedBearerFormat(bearerFormat)
		}
	case BasicScheme:
		return auth.NewAuthorizationBasicSecurityScheme(name, nil)
	default:
		return nil, NewErrUnsupportedScheme(schemeScheme)
	}
}

func mapAPIKeySchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *string) (*auth.SecurityScheme, error) {
	return auth.NewAPIKeySecurityScheme(name, auth.SchemeIn(scheme.Value.In), securitySchemeValue)
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
	}

	return auth.NewOAuthSecurityScheme(name, nil, securitySchemeValue, cfg)
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
		schemeLabel := schemeCounterLabel(schemeType, scheme.Value)

		switch schemeType {
		case HttpSchemeType:
			securitySchemes[name], err = mapHTTPSchemeType(name, scheme, value)
		case OAuth2SchemeType, OpenIdConnectSchemeType:
			var oauthValue *auth.OAuthValue
			if value != nil {
				oauthValue = auth.NewOAuthValue(*value, nil, nil, nil)
			}
			securitySchemes[name], err = mapOAuth2SchemeType(name, scheme, oauthValue)
		case ApiKeySchemeType:
			securitySchemes[name], err = mapAPIKeySchemeType(name, scheme, value)
		default:
			telemetryx.Counter(ctx, "openapi.security-scheme.unsupported", 1, schemeLabel)
			err = NewErrUnsupportedSecuritySchemeType(schemeType)
		}

		if err != nil {
			return nil, err
		}

		telemetryx.Counter(ctx, "openapi.security-scheme", 1, schemeLabel)
	}

	return securitySchemes, nil
}

// schemeCounterLabel names a security scheme for the Argvio counters from a
// fixed vocabulary, so nothing taken from the scanned spec is ever sent.
func schemeCounterLabel(schemeType string, scheme *openapi3.SecurityScheme) string {
	switch schemeType {
	case HttpSchemeType:
		return "http-" + telemetryx.Vocab(scheme.Scheme, "bearer", "basic")
	case ApiKeySchemeType:
		return "apikey-" + telemetryx.Vocab(scheme.In, "header", "query", "cookie")
	case OAuth2SchemeType, OpenIdConnectSchemeType:
		return schemeType
	default:
		return telemetryx.Vocab(schemeType, "mutualtls")
	}
}
