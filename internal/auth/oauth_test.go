package auth_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/stretchr/testify/assert"
)

func TestNewOAuthSecurityScheme(t *testing.T) {
	name := "token"
	accessToken := "abc123"
	in := auth.InHeader
	tokenFormat := auth.NoneTokenFormat
	oauthValue := auth.NewOAuthValue(accessToken, nil, nil, nil)
	oauthConfig := auth.OAuthConfig{}

	securityScheme, err := auth.NewOAuthSecurityScheme(name, &in, oauthValue, &oauthConfig)

	assert.NoError(t, err)
	assert.Equal(t, auth.OAuth2, securityScheme.GetType())
	assert.Equal(t, auth.OAuthScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, oauthValue, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestNewOAuthSecurityScheme_WhenNilIn(t *testing.T) {
	name := "token"
	accessToken := "abc123"
	oauthValue := auth.NewOAuthValue(accessToken, nil, nil, nil)
	oauthConfig := auth.OAuthConfig{}

	securityScheme, err := auth.NewOAuthSecurityScheme(name, nil, oauthValue, &oauthConfig)

	assert.NoError(t, err)
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
}

func TestNewOAuthSecurityScheme_WhenQueryIn(t *testing.T) {
	name := "token"
	accessToken := "abc123"
	in := auth.InQuery
	oauthValue := auth.NewOAuthValue(accessToken, nil, nil, nil)
	oauthConfig := auth.OAuthConfig{}

	securityScheme, err := auth.NewOAuthSecurityScheme(name, &in, oauthValue, &oauthConfig)

	assert.NoError(t, err)
	assert.Equal(t, auth.InQuery, *securityScheme.GetIn())
}

func TestNewOAuthSecurityScheme_WhenNilValue(t *testing.T) {
	name := "token"
	oauthConfig := auth.OAuthConfig{}

	securityScheme, err := auth.NewOAuthSecurityScheme(name, nil, nil, &oauthConfig)

	assert.NoError(t, err)
	assert.Equal(t, nil, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestNewOAuthSecurityScheme_WhenJWTFormatValue(t *testing.T) {
	name := "token"
	accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ufhxDTmrs4T5MSsvT6lsb3OpdWi5q8O31VX7TgrVamA"
	in := auth.InHeader
	tokenFormat := auth.JWTTokenFormat
	oauthValue := auth.NewOAuthValue(accessToken, nil, nil, nil)
	oauthConfig := auth.OAuthConfig{}

	securityScheme, err := auth.NewOAuthSecurityScheme(name, &in, oauthValue, &oauthConfig)

	assert.NoError(t, err)
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, oauthValue, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}

func TestMustNewOAuthSecurityScheme(t *testing.T) {
	name := "token"
	accessToken := "abc123"
	in := auth.InHeader
	tokenFormat := auth.NoneTokenFormat
	oauthValue := auth.NewOAuthValue(accessToken, nil, nil, nil)
	oauthConfig := auth.OAuthConfig{}

	securityScheme := auth.MustNewOAuthSecurityScheme(name, &in, oauthValue, &oauthConfig)

	assert.Equal(t, auth.OAuth2, securityScheme.GetType())
	assert.Equal(t, auth.OAuthScheme, securityScheme.GetScheme())
	assert.Equal(t, auth.InHeader, *securityScheme.GetIn())
	assert.Equal(t, &tokenFormat, securityScheme.GetTokenFormat())
	assert.Equal(t, name, securityScheme.GetName())
	assert.Equal(t, oauthValue, securityScheme.GetValidValue())
	assert.Equal(t, nil, securityScheme.GetAttackValue())
}
