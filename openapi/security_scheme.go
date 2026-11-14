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
		return auth.NewAuthorizationBasicSecurityScheme(name, nil)
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
		schemeLabel := schemeCounterLabel(schemeType, scheme.Value.Scheme, scheme.Value.In)
		formatLabel := bearerFormatLabel(schemeType, scheme.Value)

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
