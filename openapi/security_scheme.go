package openapi

import (
	"fmt"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	HttpSchemeType          string = "http"
	OAuth2SchemeType        string = "oauth2"
	OpenIdConnectSchemeType string = "openidconnect"
	ApiKeySchemeType        string = "apikey"

	// BasicScheme  string = "basic"
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

func mapHTTPSchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *string) (auth.SecurityScheme, error) {
	schemeScheme := strings.ToLower(scheme.Value.Scheme)

	switch schemeScheme {
	case BearerScheme:
		bearerFormat := strings.ToLower(scheme.Value.BearerFormat)
		if bearerFormat == "" {
			return auth.NewAuthorizationBearerSecurityScheme(name, securitySchemeValue), nil
		}

		switch bearerFormat {
		case "jwt":
			return auth.NewAuthorizationJWTBearerSecurityScheme(name, securitySchemeValue)
		default:
			return nil, NewErrUnsupportedBearerFormat(bearerFormat)
		}

	default:
		return nil, NewErrUnsupportedScheme(schemeScheme)
	}
}

func mapOAuth2SchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue *string) (auth.SecurityScheme, error) {
	if scheme.Value.Flows == nil {
		return auth.NewOAuthSecurityScheme(name, securitySchemeValue, nil), nil
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

	return auth.NewOAuthSecurityScheme(name, securitySchemeValue, cfg), nil
}

func (openapi *OpenAPI) SecuritySchemeMap(values *auth.SecuritySchemeValues) (auth.SecuritySchemesMap, error) {
	var err error
	var securitySchemeValue interface{}

	if openapi.Doc.Components == nil || openapi.Doc.Components.SecuritySchemes == nil {
		return nil, nil
	}

	securitySchemes := map[string]auth.SecurityScheme{}
	for name, scheme := range openapi.Doc.Components.SecuritySchemes {
		securitySchemeValue = values.Get(name)

		var value *string
		if securitySchemeValue != nil {
			value, _ = securitySchemeValue.(*string)
		}

		schemeType := strings.ToLower(scheme.Value.Type)
		switch schemeType {
		case HttpSchemeType:
			securitySchemes[name], err = mapHTTPSchemeType(name, scheme, value)
		case OAuth2SchemeType, OpenIdConnectSchemeType:
			securitySchemes[name], err = mapOAuth2SchemeType(name, scheme, value)
		default:
			err = NewErrUnsupportedSecuritySchemeType(schemeType)
		}

		if err != nil {
			return nil, err
		}
	}

	return securitySchemes, nil
}
