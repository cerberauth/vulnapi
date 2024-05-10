package auth

import (
	"fmt"
	"net/http"
)

type OAuthFlow string

const (
	AuthorizationCodeFlow OAuthFlow = "authorization_code"
	ImplicitFlow          OAuthFlow = "implicit"
	ClientCredentials     OAuthFlow = "client_credentials"
)

type OAuthConfig struct {
	ClientID     string
	ClientSecret string

	TokenURL   string
	RefreshURL string
}

type OAuthSecurityScheme struct {
	Type        Type
	Scheme      SchemeName
	In          SchemeIn
	Name        string
	ValidValue  *string
	AttackValue string

	Config *OAuthConfig
}

var _ SecurityScheme = (*OAuthSecurityScheme)(nil)

func NewOAuthSecurityScheme(name string, value *string, cfg *OAuthConfig) *OAuthSecurityScheme {
	return &OAuthSecurityScheme{
		Type:        HttpType,
		Scheme:      BearerScheme,
		In:          InHeader,
		Name:        name,
		ValidValue:  value,
		AttackValue: "",

		Config: cfg,
	}
}

func (ss *OAuthSecurityScheme) GetHeaders() http.Header {
	header := http.Header{}
	attackValue := ss.GetAttackValue().(string)
	if attackValue == "" && ss.ValidValue != nil {
		attackValue = *ss.ValidValue
	}

	header.Set(AuthorizationHeader, fmt.Sprintf("%s %s", BearerPrefix, attackValue))

	return header
}

func (ss *OAuthSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *OAuthSecurityScheme) HasValidValue() bool {
	return ss.ValidValue != nil
}

func (ss *OAuthSecurityScheme) GetValidValue() interface{} {
	return *ss.ValidValue
}

func (ss *OAuthSecurityScheme) GetValidValueWriter() interface{} {
	return nil
}

func (ss *OAuthSecurityScheme) SetAttackValue(v interface{}) {
	ss.AttackValue = v.(string)
}

func (ss *OAuthSecurityScheme) GetAttackValue() interface{} {
	return ss.AttackValue
}
