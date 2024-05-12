package auth

import "errors"

type SchemeName string

// Values are registred in the IANA Authentication Scheme registry
// https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
const (
	BasicScheme  SchemeName = "basic"
	BearerScheme SchemeName = "bearer"
	DigestScheme SchemeName = "digest"
	OAuthScheme  SchemeName = "oauth"
	PrivateToken SchemeName = "privateToken"
)

func (s *SchemeName) String() string {
	return string(*s)
}

func (s *SchemeName) Set(v string) error {
	switch v {
	case "basic", "bearer", "digest", "oauth", "privateToken":
		*s = SchemeName(v)
		return nil
	default:
		return errors.New(`must be one of "basic", "bearer", "digest", "oauth", "privateToken"`)
	}
}

func (e *SchemeName) Type() string {
	return "scheme"
}

type SchemeIn string

const (
	InHeader SchemeIn = "header"
	InCookie SchemeIn = "cookie"
)
