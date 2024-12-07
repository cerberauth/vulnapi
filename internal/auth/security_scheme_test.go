package auth_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/jwt"
	"github.com/stretchr/testify/assert"
)

func TestNewSecurityScheme(t *testing.T) {
	inHeader := auth.InHeader
	jwtTokenFormat := auth.JWTTokenFormat

	tests := []struct {
		name        string
		schemeName  string
		config      interface{}
		t           auth.Type
		scheme      auth.SchemeName
		in          *auth.SchemeIn
		tokenFormat *auth.TokenFormat
		expectError bool
	}{
		{
			name:        "Valid API Key in Header",
			schemeName:  "apiKey",
			config:      nil,
			t:           auth.ApiKey,
			scheme:      auth.PrivateToken,
			in:          &inHeader,
			tokenFormat: nil,
			expectError: false,
		},
		{
			name:        "Missing name with in",
			schemeName:  "",
			config:      nil,
			t:           auth.ApiKey,
			scheme:      auth.PrivateToken,
			in:          &inHeader,
			tokenFormat: nil,
			expectError: true,
		},
		{
			name:        "Missing in for API Key",
			schemeName:  "apiKey",
			config:      nil,
			t:           auth.ApiKey,
			scheme:      auth.PrivateToken,
			in:          nil,
			tokenFormat: nil,
			expectError: true,
		},
		{
			name:        "Valid HTTP Bearer",
			schemeName:  "bearer",
			config:      nil,
			t:           auth.HttpType,
			scheme:      auth.BearerScheme,
			in:          &inHeader,
			tokenFormat: &jwtTokenFormat,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityScheme, err := auth.NewSecurityScheme(tt.schemeName, tt.config, tt.t, tt.scheme, tt.in, tt.tokenFormat)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.schemeName, securityScheme.GetName())
				assert.Equal(t, tt.config, securityScheme.GetConfig())
				assert.Equal(t, tt.t, securityScheme.GetType())
				assert.Equal(t, tt.scheme, securityScheme.GetScheme())
				assert.Equal(t, tt.in, securityScheme.GetIn())
				assert.Equal(t, tt.tokenFormat, securityScheme.GetTokenFormat())
			}
		})
	}
}

func TestSetValidValue(t *testing.T) {
	inHeader := auth.InHeader
	inQuery := auth.InQuery
	inCookie := auth.InCookie
	jwtTokenFormat := auth.JWTTokenFormat

	tests := []struct {
		name            string
		schemeType      auth.Type
		schemeName      auth.SchemeName
		in              *auth.SchemeIn
		tokenFormat     *auth.TokenFormat
		value           interface{}
		expectError     bool
		expectedMessage string
	}{
		{
			name:            "Valid API Key in Header",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			value:           "valid-api-key",
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid API Key in Header",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			value:           &http.Header{"token": []string{"invalid-api-key"}},
			expectError:     true,
			expectedMessage: "invalid value for api key security scheme",
		},
		{
			name:            "Valid API Key in Query",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inQuery,
			tokenFormat:     nil,
			value:           "valid-api-key",
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Valid API Key in Cookie",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inCookie,
			tokenFormat:     nil,
			value:           http.Cookie{Name: "token", Value: "valid-api-key"},
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Valid HTTP Bearer with JWT",
			schemeType:      auth.HttpType,
			schemeName:      auth.BearerScheme,
			in:              &inHeader,
			tokenFormat:     &jwtTokenFormat,
			value:           jwt.FakeJWT,
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid HTTP Bearer with JWT",
			schemeType:      auth.HttpType,
			schemeName:      auth.BearerScheme,
			in:              &inHeader,
			tokenFormat:     &jwtTokenFormat,
			value:           "invalid-jwt",
			expectError:     true,
			expectedMessage: "token is malformed: token contains an invalid number of segments",
		},
		{
			name:            "Valid OAuth2",
			schemeType:      auth.OAuth2,
			schemeName:      auth.PrivateToken,
			in:              nil,
			tokenFormat:     nil,
			value:           &auth.OAuthValue{},
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid OAuth2",
			schemeType:      auth.OAuth2,
			schemeName:      auth.PrivateToken,
			in:              nil,
			tokenFormat:     nil,
			value:           "invalid-oauth2",
			expectError:     true,
			expectedMessage: "invalid value for oauth2 security scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityScheme, err := auth.NewSecurityScheme("testScheme", nil, tt.schemeType, tt.schemeName, tt.in, tt.tokenFormat)
			assert.NoError(t, err)

			err = securityScheme.SetValidValue(tt.value)
			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedMessage, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, securityScheme.GetValidValue())
			}
		})
	}
}

func TestSetTokenFormat(t *testing.T) {
	inHeader := auth.InHeader
	jwtTokenFormat := auth.JWTTokenFormat

	tests := []struct {
		name            string
		initialValue    interface{}
		tokenFormat     auth.TokenFormat
		expectError     bool
		expectedMessage string
	}{
		{
			name:            "Valid JWT Token Format",
			initialValue:    jwt.FakeJWT,
			tokenFormat:     jwtTokenFormat,
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid JWT Token Format",
			initialValue:    "invalid-token",
			tokenFormat:     jwtTokenFormat,
			expectError:     true,
			expectedMessage: "token format should be jwt",
		},
		{
			name:            "Non-JWT Token Format",
			initialValue:    "some-value",
			tokenFormat:     auth.TokenFormat("non-jwt"),
			expectError:     false,
			expectedMessage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityScheme, err := auth.NewSecurityScheme("testScheme", nil, auth.HttpType, auth.BearerScheme, &inHeader, nil)
			assert.NoError(t, err)

			err = securityScheme.SetValidValue(tt.initialValue)
			assert.NoError(t, err)

			err = securityScheme.SetTokenFormat(tt.tokenFormat)
			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedMessage, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, &tt.tokenFormat, securityScheme.GetTokenFormat())
			}
		})
	}
}

func TestSetAttackValue(t *testing.T) {
	inHeader := auth.InHeader
	inQuery := auth.InQuery
	inCookie := auth.InCookie
	jwtTokenFormat := auth.JWTTokenFormat

	tests := []struct {
		name            string
		schemeType      auth.Type
		schemeName      auth.SchemeName
		in              *auth.SchemeIn
		tokenFormat     *auth.TokenFormat
		value           interface{}
		expectError     bool
		expectedMessage string
	}{
		{
			name:            "Valid API Key in Header",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			value:           "valid-api-key",
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid API Key in Header",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			value:           &http.Header{"token": []string{"invalid-api-key"}},
			expectError:     true,
			expectedMessage: "invalid value for api key security scheme",
		},
		{
			name:            "Valid API Key in Query",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inQuery,
			tokenFormat:     nil,
			value:           "valid-api-key",
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Valid API Key in Cookie",
			schemeType:      auth.ApiKey,
			schemeName:      auth.PrivateToken,
			in:              &inCookie,
			tokenFormat:     nil,
			value:           http.Cookie{Name: "token", Value: "valid-api-key"},
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Valid HTTP Bearer with JWT",
			schemeType:      auth.HttpType,
			schemeName:      auth.BearerScheme,
			in:              &inHeader,
			tokenFormat:     &jwtTokenFormat,
			value:           jwt.FakeJWT,
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid HTTP Bearer with JWT",
			schemeType:      auth.HttpType,
			schemeName:      auth.BearerScheme,
			in:              &inHeader,
			tokenFormat:     &jwtTokenFormat,
			value:           "invalid-jwt",
			expectError:     true,
			expectedMessage: "token is malformed: token contains an invalid number of segments",
		},
		{
			name:            "Valid OAuth2",
			schemeType:      auth.OAuth2,
			schemeName:      auth.PrivateToken,
			in:              nil,
			tokenFormat:     nil,
			value:           &auth.OAuthValue{},
			expectError:     false,
			expectedMessage: "",
		},
		{
			name:            "Invalid OAuth2",
			schemeType:      auth.OAuth2,
			schemeName:      auth.PrivateToken,
			in:              nil,
			tokenFormat:     nil,
			value:           "invalid-oauth2",
			expectError:     true,
			expectedMessage: "invalid value for oauth2 security scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityScheme, err := auth.NewSecurityScheme("testScheme", nil, tt.schemeType, tt.schemeName, tt.in, tt.tokenFormat)
			assert.NoError(t, err)

			err = securityScheme.SetAttackValue(tt.value)
			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedMessage, err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, securityScheme.GetAttackValue())
			}
		})
	}
}

func TestGetHeaders(t *testing.T) {
	inHeader := auth.InHeader
	jwtTokenFormat := auth.JWTTokenFormat

	tests := []struct {
		name            string
		schemeName      string
		schemeType      auth.Type
		scheme          auth.SchemeName
		in              *auth.SchemeIn
		tokenFormat     *auth.TokenFormat
		validValue      interface{}
		attackValue     interface{}
		expectedHeaders http.Header
	}{
		{
			name:            "API Key in Header with Valid Value",
			schemeName:      "X-Api-Key",
			schemeType:      auth.ApiKey,
			scheme:          auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			validValue:      "valid-api-key",
			attackValue:     nil,
			expectedHeaders: http.Header{"X-Api-Key": []string{"valid-api-key"}},
		},
		{
			name:            "API Key in Header with Attack Value",
			schemeName:      "X-Api-Key",
			schemeType:      auth.ApiKey,
			scheme:          auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			validValue:      "valid-api-key",
			attackValue:     "attack-api-key",
			expectedHeaders: http.Header{"X-Api-Key": []string{"attack-api-key"}},
		},
		{
			name:            "HTTP Bearer with JWT",
			schemeName:      "Bearer",
			schemeType:      auth.HttpType,
			scheme:          auth.BearerScheme,
			in:              &inHeader,
			tokenFormat:     &jwtTokenFormat,
			validValue:      jwt.FakeJWT,
			attackValue:     nil,
			expectedHeaders: http.Header{"Authorization": []string{fmt.Sprintf("%s %s", auth.BearerPrefix, jwt.FakeJWT)}},
		},
		{
			name:            "HTTP Bearer with Attack JWT",
			schemeName:      "Bearer",
			schemeType:      auth.HttpType,
			scheme:          auth.BearerScheme,
			in:              &inHeader,
			tokenFormat:     &jwtTokenFormat,
			validValue:      jwt.FakeJWT,
			attackValue:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.",
			expectedHeaders: http.Header{"Authorization": []string{fmt.Sprintf("%s %s", auth.BearerPrefix, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.")}},
		},
		{
			name:            "No Valid or Attack Value",
			schemeName:      "X-Api-Key",
			schemeType:      auth.ApiKey,
			scheme:          auth.PrivateToken,
			in:              &inHeader,
			tokenFormat:     nil,
			validValue:      nil,
			attackValue:     nil,
			expectedHeaders: http.Header{},
		},
		{
			name:            "HTTP Basic with valid credentials",
			schemeName:      "Basic",
			schemeType:      auth.HttpType,
			scheme:          auth.BasicScheme,
			in:              &inHeader,
			tokenFormat:     nil,
			validValue:      auth.NewHTTPBasicCredentials("user", "password"),
			attackValue:     nil,
			expectedHeaders: http.Header{"Authorization": []string{fmt.Sprintf("%s %s", auth.BasicPrefix, "dXNlcjpwYXNzd29yZA==")}},
		},
		{
			name:            "HTTP Basic with attack credentials",
			schemeName:      "Basic",
			schemeType:      auth.HttpType,
			scheme:          auth.BasicScheme,
			in:              &inHeader,
			tokenFormat:     nil,
			validValue:      auth.NewHTTPBasicCredentials("user", "password"),
			attackValue:     auth.NewHTTPBasicCredentials("user", "attack-password"),
			expectedHeaders: http.Header{"Authorization": []string{fmt.Sprintf("%s %s", auth.BasicPrefix, "dXNlcjphdHRhY2stcGFzc3dvcmQ=")}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			securityScheme, err := auth.NewSecurityScheme(tt.schemeName, nil, tt.schemeType, tt.scheme, tt.in, tt.tokenFormat)
			assert.NoError(t, err)

			err = securityScheme.SetValidValue(tt.validValue)
			assert.NoError(t, err)

			err = securityScheme.SetAttackValue(tt.attackValue)
			assert.NoError(t, err)

			headers := securityScheme.GetHeaders()
			assert.Equal(t, tt.expectedHeaders, headers)
		})
	}
}
