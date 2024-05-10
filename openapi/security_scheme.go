package openapi

import (
	"fmt"
	"strings"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/getkin/kin-openapi/openapi3"
)

const (
	HttpSchemeType string = "http"
	// OAuth2SchemeType        string = "oauth2"
	// OpenIdConnectSchemeType string = "openIdConnect"
	// ApiKeySchemeType        string = "apiKey"

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

func mapHTTPSchemeType(name string, scheme *openapi3.SecuritySchemeRef, securitySchemeValue interface{}) (auth.SecurityScheme, error) {
	schemeScheme := strings.ToLower(scheme.Value.Scheme)

	value, ok := securitySchemeValue.(*string)
	if !ok {
		return nil, fmt.Errorf("invalid security scheme value type: %T", securitySchemeValue)
	}

	switch schemeScheme {
	case BearerScheme:
		bearerFormat := strings.ToLower(scheme.Value.BearerFormat)
		if bearerFormat == "" {
			return auth.NewAuthorizationBearerSecurityScheme(name, value), nil
		}

		switch bearerFormat {
		case "jwt":
			return auth.NewAuthorizationJWTBearerSecurityScheme(name, value)
		default:
			return nil, NewErrUnsupportedBearerFormat(bearerFormat)
		}

	default:
		return nil, NewErrUnsupportedScheme(schemeScheme)
	}
}

func (openapi *OpenAPI) SecuritySchemeMap(values auth.SecuritySchemeValues) (auth.SecuritySchemesMap, error) {
	var err error
	var securitySchemeValue interface{}

	securitySchemes := map[string]auth.SecurityScheme{}
	for name, scheme := range openapi.doc.Components.SecuritySchemes {
		securitySchemeValue = values.Values[name]
		if securitySchemeValue == nil {
			securitySchemeValue = values.Default
		}

		schemeType := strings.ToLower(scheme.Value.Type)
		switch schemeType {
		case HttpSchemeType:
			securitySchemes[name], err = mapHTTPSchemeType(name, scheme, securitySchemeValue)
		}

		if err != nil {
			return nil, err
		}
	}

	return securitySchemes, nil
}
