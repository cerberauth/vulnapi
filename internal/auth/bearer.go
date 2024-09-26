package auth

import (
	"fmt"
	"net/http"
)

type BearerSecurityScheme struct {
	Type        Type       `json:"type" yaml:"type"`
	Scheme      SchemeName `json:"scheme" yaml:"scheme"`
	In          SchemeIn   `json:"in" yaml:"in"`
	Name        string     `json:"name" yaml:"name"`
	ValidValue  *string    `json:"-" yaml:"-"`
	AttackValue string     `json:"-" yaml:"-"`
}

var _ SecurityScheme = (*BearerSecurityScheme)(nil)

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

func (ss *BearerSecurityScheme) GetType() Type {
	return ss.Type
}

func (ss *BearerSecurityScheme) GetScheme() SchemeName {
	return ss.Scheme
}

func (ss *BearerSecurityScheme) GetIn() *SchemeIn {
	return &ss.In
}

func (ss *BearerSecurityScheme) GetName() string {
	return ss.Name
}

func (ss *BearerSecurityScheme) GetHeaders() http.Header {
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

func (ss *BearerSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *BearerSecurityScheme) HasValidValue() bool {
	return ss.ValidValue != nil && *ss.ValidValue != ""
}

func (ss *BearerSecurityScheme) GetValidValue() interface{} {
	if !ss.HasValidValue() {
		return nil
	}

	return *ss.ValidValue
}

func (ss *BearerSecurityScheme) GetValidValueWriter() interface{} {
	return nil
}

func (ss *BearerSecurityScheme) SetAttackValue(v interface{}) {
	ss.AttackValue = v.(string)
}

func (ss *BearerSecurityScheme) GetAttackValue() interface{} {
	return ss.AttackValue
}
