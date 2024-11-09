package auth

import (
	"net/http"
)

type SecurityScheme interface {
	GetType() Type
	GetScheme() SchemeName
	GetIn() *SchemeIn
	GetName() string

	GetHeaders() http.Header
	GetCookies() []*http.Cookie
	GetValidValue() interface{}
	HasValidValue() bool
	GetValidValueWriter() interface{}
	SetAttackValue(v interface{})
	GetAttackValue() interface{}
}
type SecuritySchemesMap map[string]SecurityScheme

func GetSecuritySchemeUniqueName(securityScheme SecurityScheme) string {
	if securityScheme == nil {
		return ""
	}

	uniqueName := string(securityScheme.GetType()) + "-" + string(securityScheme.GetScheme())
	if securityScheme.GetIn() != nil {
		uniqueName += "-" + string(*securityScheme.GetIn())
	}

	return uniqueName
}
