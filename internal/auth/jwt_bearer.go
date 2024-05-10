package auth

import (
	"fmt"
	"net/http"

	"github.com/cerberauth/vulnapi/jwt"
)

type JWTBearerSecurityScheme struct {
	Type        Type
	Scheme      SchemeName
	In          SchemeIn
	Name        string
	ValidValue  *string
	JWTWriter   *jwt.JWTWriter
	AttackValue string
}

var _ SecurityScheme = (*JWTBearerSecurityScheme)(nil)

func NewAuthorizationJWTBearerSecurityScheme(name string, value *string) (*JWTBearerSecurityScheme, error) {
	if value == nil {
		fakeJWT := jwt.FakeJWT
		value = &fakeJWT
	}

	jwtWriter, err := jwt.NewJWTWriter(*value)
	if err != nil {
		return nil, err
	}

	return &JWTBearerSecurityScheme{
		Type:        HttpType,
		Scheme:      BearerScheme,
		In:          InHeader,
		Name:        name,
		ValidValue:  value,
		JWTWriter:   jwtWriter,
		AttackValue: "",
	}, nil
}

func (ss *JWTBearerSecurityScheme) GetHeaders() http.Header {
	header := http.Header{}
	attackValue := ss.GetAttackValue().(string)
	if attackValue == "" && ss.ValidValue != nil {
		attackValue = *ss.ValidValue
	}

	header.Set(AuthorizationHeader, fmt.Sprintf("%s %s", BearerPrefix, attackValue))

	return header
}

func (ss *JWTBearerSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *JWTBearerSecurityScheme) HasValidValue() bool {
	return ss.ValidValue != nil
}

func (ss *JWTBearerSecurityScheme) GetValidValue() interface{} {
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
