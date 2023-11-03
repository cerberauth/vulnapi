package auth

import (
	"fmt"
	"net/http"
)

type BearerSecurityScheme struct {
	Type        Type
	Scheme      Scheme
	In          SchemeIn
	Name        string
	ValidValue  *string
	AttackValue string
}

func NewAuthorizationBearerSecurityScheme(name string, value *string) *BearerSecurityScheme {
	return &BearerSecurityScheme{
		Type:        HttpType,
		Scheme:      BearerScheme,
		In:          InHeader,
		Name:        name,
		ValidValue:  value,
		AttackValue: "",
	}
}

func (ss *BearerSecurityScheme) GetHeaders() http.Header {
	header := http.Header{}
	if ss.ValidValue != nil {
		header.Set("Authorization", fmt.Sprintf("Bearer %s", *ss.ValidValue))
	}

	return header
}

func (ss *BearerSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *BearerSecurityScheme) GetValidValue() interface{} {
	return *ss.ValidValue
}

func (ss *BearerSecurityScheme) SetAttackValue(v interface{}) {
	ss.AttackValue = v.(string)
}

func (ss *BearerSecurityScheme) GetAttackValue() interface{} {
	return ss.AttackValue
}
