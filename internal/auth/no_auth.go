package auth

import "net/http"

type NoAuthSecurityScheme struct{}

var _ SecurityScheme = (*NoAuthSecurityScheme)(nil)

func NewNoAuthSecurityScheme() *NoAuthSecurityScheme {
	return &NoAuthSecurityScheme{}
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
