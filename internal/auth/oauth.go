package auth

import (
	"time"

	jwtop "github.com/cerberauth/jwtop/jwt"
)

type OAuthFlow string

const (
	AuthorizationCodeFlow OAuthFlow = "authorization_code"
	ImplicitFlow          OAuthFlow = "implicit"
	ClientCredentials     OAuthFlow = "client_credentials"
)

type OAuthValue struct {
	AccessToken  string     `json:"access_token" yaml:"access_token"`   //nolint:gosec
	RefreshToken *string    `json:"refresh_token" yaml:"refresh_token"` //nolint:gosec
	ExpiresIn    *time.Time `json:"expires_in" yaml:"expires_in"`
	Scope        *string    `json:"scope" yaml:"scope"`
}

func NewOAuthValue(accessToken string, refreshToken *string, expiresIn *time.Time, scope *string) *OAuthValue {
	return &OAuthValue{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		Scope:        scope,
	}
}

func (value *OAuthValue) SetAccessToken(accessToken string) {
	value.AccessToken = accessToken
}

func (value *OAuthValue) GetAccessToken() string {
	return value.AccessToken
}

type OAuthConfig struct {
	ClientID     string
	ClientSecret string //nolint:gosec

	TokenURL   string
	RefreshURL string
}

var defaultIn = InHeader

func NewOAuthSecurityScheme(name string, in *SchemeIn, value *OAuthValue, config *OAuthConfig) (*SecurityScheme, error) {
	if in == nil {
		in = &defaultIn
	}

	securityScheme, err := NewSecurityScheme(name, config, OAuth2, OAuthScheme, in, nil)
	if err != nil {
		return nil, err
	}

	if value != nil && value.AccessToken != "" {
		err = securityScheme.SetValidValue(value)
		if err != nil {
			return nil, err
		}

		var tokenFormat TokenFormat
		if jwtop.IsJWT(value.AccessToken) {
			tokenFormat = JWTTokenFormat
		} else {
			tokenFormat = NoneTokenFormat
		}
		if err = securityScheme.SetTokenFormat(tokenFormat); err != nil {
			return nil, err
		}
	}

	return securityScheme, nil
}

func MustNewOAuthSecurityScheme(name string, in *SchemeIn, value *OAuthValue, config *OAuthConfig) *SecurityScheme {
	securityScheme, err := NewOAuthSecurityScheme(name, in, value, config)
	if err != nil {
		panic(err)
	}

	return securityScheme
}
