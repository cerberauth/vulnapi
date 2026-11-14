package openapi

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
)

func TestSchemeCounterLabel(t *testing.T) {
	tests := []struct {
		name       string
		schemeType string
		scheme     string
		in         string
		want       string
	}{
		{"http bearer", HttpSchemeType, "Bearer", "", "http-bearer"},
		{"http basic", HttpSchemeType, "basic", "", "http-basic"},
		{"http digest is not echoed", HttpSchemeType, "digest", "", "http-other"},
		{"api key in header", ApiKeySchemeType, "", "header", "apikey-header"},
		{"api key in unknown place is not echoed", ApiKeySchemeType, "", "x-secret", "apikey-other"},
		{"oauth2", OAuth2SchemeType, "", "", "oauth2"},
		{"openid connect", OpenIdConnectSchemeType, "", "", "openidconnect"},
		{"mutual tls", "mutualtls", "", "", "mutualtls"},
		{"unknown type is not echoed", "my-custom-scheme", "", "", "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, schemeCounterLabel(tt.schemeType, tt.scheme, tt.in))
		})
	}
}

func TestBearerFormatLabel(t *testing.T) {
	tests := []struct {
		name       string
		schemeType string
		scheme     openapi3.SecurityScheme
		want       string
	}{
		{"jwt", HttpSchemeType, openapi3.SecurityScheme{Scheme: "bearer", BearerFormat: "JWT"}, "jwt"},
		{"other format is not echoed", HttpSchemeType, openapi3.SecurityScheme{Scheme: "bearer", BearerFormat: "my-token"}, "other"},
		{"bearer without format", HttpSchemeType, openapi3.SecurityScheme{Scheme: "bearer"}, "none"},
		{"basic ignores format", HttpSchemeType, openapi3.SecurityScheme{Scheme: "basic", BearerFormat: "JWT"}, "none"},
		{"api key ignores format", ApiKeySchemeType, openapi3.SecurityScheme{BearerFormat: "JWT"}, "none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bearerFormatLabel(tt.schemeType, &tt.scheme))
		})
	}
}

func TestSupportedLabel(t *testing.T) {
	assert.Equal(t, "no", supportedLabel(NewErrUnsupportedSecuritySchemeType("other")))
	assert.Equal(t, "no", supportedLabel(NewErrUnsupportedScheme("digest")))
	assert.Equal(t, "error", supportedLabel(assert.AnError))
}

// The labels recordOperationSchemes builds from an operation's schemes must
// be the same as the ones SecuritySchemeMap builds from the spec, so the two
// counters can be read together.
func TestOperationSchemeLabelsMatchSpecLabels(t *testing.T) {
	bearer, err := auth.NewAuthorizationBearerSecurityScheme("bearer", nil)
	assert.NoError(t, err)
	apiKey, err := auth.NewAPIKeySecurityScheme("key", auth.InCookie, nil)
	assert.NoError(t, err)

	assert.Equal(t, "http-bearer", operationSchemeLabel(bearer))
	assert.Equal(t, "apikey-cookie", operationSchemeLabel(apiKey))
}

func TestMediaTypeLabel(t *testing.T) {
	for in, want := range map[string]string{
		"application/json":                  "json",
		"application/json; charset=utf-8":   "json",
		"application/vnd.acme.v1+json":      "json",
		"application/xml":                   "xml",
		"application/soap+xml":              "xml",
		"application/x-www-form-urlencoded": "form",
		"multipart/form-data":               "multipart",
		"application/octet-stream":          "binary",
		"text/plain":                        "text",
		"application/vnd.acme.secret":       "other",
		"not a media type":                  "other",
		"":                                  "other",
	} {
		assert.Equal(t, want, mediaTypeLabel(in), in)
	}
}
