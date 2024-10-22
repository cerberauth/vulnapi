package auth

import (
	"fmt"
	"net/http"

	"github.com/cerberauth/vulnapi/jwt"
)

type JWTBearerSecurityScheme struct {
	Type        Type       `json:"type" yaml:"type"`
	Scheme      SchemeName `json:"scheme" yaml:"scheme"`
	In          SchemeIn   `json:"in" yaml:"in"`
	Name        string     `json:"name" yaml:"name"`
	ValidValue  *string    `json:"-" yaml:"-"`
	AttackValue string     `json:"-" yaml:"-"`

	JWTWriter *jwt.JWTWriter `json:"-" yaml:"-"`
}

var _ SecurityScheme = (*JWTBearerSecurityScheme)(nil)

func NewAuthorizationJWTBearerSecurityScheme(name string, value *string) (*JWTBearerSecurityScheme, error) {
	var jwtWriter *jwt.JWTWriter
	if value != nil {
		var err error
		if jwtWriter, err = jwt.NewJWTWriter(*value); err != nil {
			return nil, err
		}
	}

	return &JWTBearerSecurityScheme{
		Type:        HttpType,
		Scheme:      BearerScheme,
		In:          InHeader,
		Name:        name,
		ValidValue:  value,
		AttackValue: "",

		JWTWriter: jwtWriter,
	}, nil
}

func MustNewAuthorizationJWTBearerSecurityScheme(name string, value *string) *JWTBearerSecurityScheme {
	scheme, err := NewAuthorizationJWTBearerSecurityScheme(name, value)
	if err != nil {
		panic(err)
	}
	return scheme
}

func (ss *JWTBearerSecurityScheme) GetType() Type {
	return ss.Type
}

func (ss *JWTBearerSecurityScheme) GetScheme() SchemeName {
	return ss.Scheme
}

func (ss *JWTBearerSecurityScheme) GetIn() *SchemeIn {
	return &ss.In
}

func (ss *JWTBearerSecurityScheme) GetName() string {
	return ss.Name
}

func (ss *JWTBearerSecurityScheme) GetHeaders() http.Header {
	header := http.Header{}
	attackValue := ss.GetAttackValue().(string)
	if attackValue == "" && ss.HasValidValue() {
		attackValue = ss.GetValidValue().(string)
	}

	if attackValue != "" {
		header.Set(AuthorizationHeader, fmt.Sprintf("%s %s", BearerPrefix, attackValue))
	}

	return header
}

func (ss *JWTBearerSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *JWTBearerSecurityScheme) HasValidValue() bool {
	return ss.ValidValue != nil
}

func (ss *JWTBearerSecurityScheme) GetValidValue() interface{} {
	if !ss.HasValidValue() {
		return nil
	}

	return *ss.ValidValue
}

func (ss *JWTBearerSecurityScheme) GetValidValueWriter() interface{} {
	return ss.JWTWriter
}

func (ss *JWTBearerSecurityScheme) SetAttackValue(v interface{}) {
	ss.AttackValue = v.(string)
}

func (ss *JWTBearerSecurityScheme) GetAttackValue() interface{} {
	return ss.AttackValue
}
