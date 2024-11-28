package auth

type SchemeName string

// Values are registred in the IANA Authentication Scheme registry
// https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml
const (
	BasicScheme  SchemeName = "Basic"
	BearerScheme SchemeName = "Bearer"
	DigestScheme SchemeName = "Digest"
	OAuthScheme  SchemeName = "OAuth"
	PrivateToken SchemeName = "PrivateToken"
	NoneScheme   SchemeName = "None"
)

func (s *SchemeName) String() string {
	return string(*s)
}

func (e *SchemeName) Type() string {
	return "scheme"
}

type SchemeIn string

const (
	InQuery  SchemeIn = "query"
	InHeader SchemeIn = "header"
	InCookie SchemeIn = "cookie"
)

type TokenFormat string

const (
	JWTTokenFormat  TokenFormat = "jwt"
	NoneTokenFormat TokenFormat = "none"
)
