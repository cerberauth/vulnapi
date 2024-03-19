package auth

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cerberauth/vulnapi/jwt"
)

type BearerSecurityScheme struct {
	Type        Type
	Scheme      SchemeName
	In          SchemeIn
	Name        string
	ValidValue  *string
	TokenWriter *jwt.JWTWriter
	IsJWT       bool
	AttackValue string
}

var _ SecurityScheme = (*BearerSecurityScheme)(nil)

func NewAuthorizationBearerSecurityScheme(name string, value *string) *BearerSecurityScheme {
	var tokenWriter *jwt.JWTWriter

	if value != nil {
		var err error
		if tokenWriter, err = jwt.NewJWTWriter(*value); err != nil {
			log.Default().Println("Error creating JWT writer: ", err)
		}
	}

	return &BearerSecurityScheme{
		Type:        HttpType,
		Scheme:      BearerScheme,
		In:          InHeader,
		Name:        name,
		ValidValue:  value,
		TokenWriter: tokenWriter,
		AttackValue: "",
	}
}

func (ss *BearerSecurityScheme) GetHeaders() http.Header {
	header := http.Header{}
	if ss.ValidValue != nil {
		header.Set(AuthorizationHeader, fmt.Sprintf("%s %s", BearerPrefix, ss.GetAttackValue().(string)))
	}

	return header
}

func (ss *BearerSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *BearerSecurityScheme) GetValidValue() interface{} {
	return *ss.ValidValue
}

func (ss *BearerSecurityScheme) GetValidValueWriter() interface{} {
	return ss.TokenWriter
}

func (ss *BearerSecurityScheme) SetAttackValue(v interface{}) {
	ss.AttackValue = v.(string)
}

func (ss *BearerSecurityScheme) GetAttackValue() interface{} {
	return ss.AttackValue
}
