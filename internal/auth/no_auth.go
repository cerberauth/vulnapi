package auth

import "net/http"

type NoAuthSecurityScheme struct {
	Name   string     `json:"name" yaml:"name"`
	Type   Type       `json:"type" yaml:"type"`
	Scheme SchemeName `json:"scheme" yaml:"scheme"`
}

var _ SecurityScheme = (*NoAuthSecurityScheme)(nil)

func NewNoAuthSecurityScheme() *NoAuthSecurityScheme {
	return &NoAuthSecurityScheme{
		Name:   "",
		Type:   None,
		Scheme: NoneScheme,
	}
}

func (ss *NoAuthSecurityScheme) GetType() Type {
	return ss.Type
}

func (ss *NoAuthSecurityScheme) GetScheme() SchemeName {
	return ss.Scheme
}

func (ss *NoAuthSecurityScheme) GetIn() *SchemeIn {
	return nil
}

func (ss *NoAuthSecurityScheme) GetName() string {
	return ss.Name
}

func (ss *NoAuthSecurityScheme) GetHeaders() http.Header {
	return http.Header{}
}

func (ss *NoAuthSecurityScheme) GetCookies() []*http.Cookie {
	return []*http.Cookie{}
}

func (ss *NoAuthSecurityScheme) HasValidValue() bool {
	return false
}

func (ss *NoAuthSecurityScheme) GetValidValue() interface{} {
	return ""
}

func (ss *NoAuthSecurityScheme) GetValidValueWriter() interface{} {
	return ""
}

func (ss *NoAuthSecurityScheme) SetAttackValue(v interface{}) {}

func (ss *NoAuthSecurityScheme) GetAttackValue() interface{} {
	return nil
}
