package auth

import (
	"fmt"
	"net/http"

	"github.com/cerberauth/vulnapi/jwt"
)

func NewErrTokenFormatShouldBeJWT() error {
	return fmt.Errorf("token format should be jwt")
}

type SecurityScheme struct {
	Type        Type         `json:"type" yaml:"type"`
	Scheme      SchemeName   `json:"scheme" yaml:"scheme"`
	In          *SchemeIn    `json:"in" yaml:"in"`
	TokenFormat *TokenFormat `json:"tokenFormat" yaml:"tokenFormat"`

	Name   string      `json:"name" yaml:"name"`
	Config interface{} `json:"config" yaml:"config"`

	ValidValue  interface{} `json:"-" yaml:"-"`
	AttackValue interface{} `json:"-" yaml:"-"`
}
type SecuritySchemesMap map[string]*SecurityScheme

type InQueryValue = string
type InHeaderValue = string
type InCookieValue = http.Cookie

func NewSecurityScheme(name string, config interface{}, t Type, scheme SchemeName, in *SchemeIn, tokenFormat *TokenFormat) (*SecurityScheme, error) {
	if in != nil && name == "" {
		return nil, fmt.Errorf("name is required for security scheme with in %s", *in)
	}

	if t == ApiKey && in == nil {
		return nil, fmt.Errorf("in is required for security scheme with type %s", t)
	}

	return &SecurityScheme{
		Name:   name,
		Config: config,

		Type:        t,
		Scheme:      scheme,
		In:          in,
		TokenFormat: tokenFormat,
	}, nil
}

func (securityScheme *SecurityScheme) GetType() Type {
	return securityScheme.Type
}

func (securityScheme *SecurityScheme) GetScheme() SchemeName {
	return securityScheme.Scheme
}

func (securityScheme *SecurityScheme) GetIn() *SchemeIn {
	return securityScheme.In
}

func (securityScheme *SecurityScheme) GetToken() string {
	if !securityScheme.HasValidValue() {
		return ""
	}
	switch securityScheme.GetType() {
	case OAuth2:
		return securityScheme.GetValidValue().(*OAuthValue).GetAccessToken()
	default:
		return securityScheme.GetValidValue().(string)
	}
}

func (securityScheme *SecurityScheme) SetTokenFormat(tokenFormat TokenFormat) error {
	if tokenFormat == JWTTokenFormat && securityScheme.HasValidValue() && !jwt.IsJWT(securityScheme.GetToken()) {
		return NewErrTokenFormatShouldBeJWT()
	}

	securityScheme.TokenFormat = &tokenFormat
	return nil
}

func (securityScheme *SecurityScheme) GetTokenFormat() *TokenFormat {
	return securityScheme.TokenFormat
}

func (securityScheme *SecurityScheme) GetName() string {
	return securityScheme.Name
}

func (securityScheme *SecurityScheme) GetConfig() interface{} {
	return securityScheme.Config
}

func (securityScheme *SecurityScheme) validateValue(value interface{}) error {
	if value == nil {
		return fmt.Errorf("value is required")
	}

	switch securityScheme.GetType() {
	case ApiKey:
		if securityScheme.GetIn() == nil {
			return fmt.Errorf("in is required for api key security scheme")
		}

		var ok bool
		switch *securityScheme.GetIn() {
		case InQuery:
			_, ok = value.(InQueryValue)
		case InHeader:
			_, ok = value.(InHeaderValue)
		case InCookie:
			_, ok = value.(InCookieValue)
		}
		if !ok {
			return fmt.Errorf("invalid value for api key security scheme")
		}
		return nil

	case HttpType:
		switch securityScheme.GetScheme() {
		case BasicScheme:
			_, ok := value.(*HTTPBasicCredentials)
			if !ok {
				return fmt.Errorf("invalid value for http basic security scheme")
			}
			return nil
		default:
			val, ok := value.(string)
			if !ok {
				return fmt.Errorf("invalid value for http security scheme")
			}
			if securityScheme.GetTokenFormat() != nil && *securityScheme.GetTokenFormat() == JWTTokenFormat {
				if _, err := jwt.NewJWTWriter(val); err != nil {
					return err
				}
			}
			return nil
		}

	case OAuth2:
		_, ok := value.(*OAuthValue)
		if !ok {
			return fmt.Errorf("invalid value for oauth2 security scheme")
		}
		return nil
	}

	return nil
}

func (securityScheme *SecurityScheme) SetValidValue(value interface{}) error {
	if value == nil {
		securityScheme.ValidValue = nil
		return nil
	}

	if err := securityScheme.validateValue(value); err != nil {
		return err
	}

	securityScheme.ValidValue = value
	return nil
}

func (securityScheme *SecurityScheme) GetValidValue() interface{} {
	return securityScheme.ValidValue
}

func (securityScheme *SecurityScheme) HasValidValue() bool {
	return securityScheme.GetValidValue() != nil
}

func (securityScheme *SecurityScheme) SetAttackValue(value interface{}) error {
	if value == nil {
		securityScheme.AttackValue = nil
		return nil
	}

	if err := securityScheme.validateValue(value); err != nil {
		return err
	}

	securityScheme.AttackValue = value
	return nil
}

func (securityScheme *SecurityScheme) GetAttackValue() interface{} {
	return securityScheme.AttackValue
}

func (securityScheme *SecurityScheme) GetHeaders() http.Header {
	header := http.Header{}
	if securityScheme.GetIn() == nil || *securityScheme.GetIn() != InHeader {
		return header
	}

	attackValue := securityScheme.GetAttackValue()
	if attackValue == nil && securityScheme.HasValidValue() {
		attackValue = securityScheme.GetValidValue()
	}
	if attackValue == nil {
		return header
	}

	switch securityScheme.GetType() {
	case HttpType:
		var val string
		switch securityScheme.GetScheme() {
		case BasicScheme:
			credentials := attackValue.(*HTTPBasicCredentials)
			val = fmt.Sprintf("%s %s", BasicPrefix, credentials.Encode())
		case BearerScheme:
			val = fmt.Sprintf("%s %s", BearerPrefix, attackValue)
		default:
			val = fmt.Sprintf("%s", attackValue)
		}
		if val != "" {
			header.Set(AuthorizationHeader, val)
		}
	case ApiKey:
		if val := fmt.Sprintf("%s", attackValue); val != "" {
			header.Set(securityScheme.GetName(), val)
		}
	}

	return header
}

func (securityScheme *SecurityScheme) GetCookies() []*http.Cookie {
	if securityScheme.GetIn() == nil || *securityScheme.GetIn() != InCookie {
		return []*http.Cookie{}
	}

	cookies := []*http.Cookie{}
	// TODO
	return cookies
}
