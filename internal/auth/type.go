package auth

type Type string

const (
	HttpType      Type = "http"
	OAuth2        Type = "oauth2"
	OpenIdConnect Type = "openIdConnect"
	ApiKey        Type = "apiKey"
	None          Type = "none"
)
