package auth

import "encoding/base64"

type HTTPBasicCredentials struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

func NewHTTPBasicCredentials(username string, password string) *HTTPBasicCredentials {
	return &HTTPBasicCredentials{
		Username: username,
		Password: password,
	}
}

func (credentials *HTTPBasicCredentials) GetUsername() string {
	return credentials.Username
}

func (credentials *HTTPBasicCredentials) GetPassword() string {
	return credentials.Password
}

func (credentials *HTTPBasicCredentials) Encode() string {
	return base64.StdEncoding.EncodeToString([]byte(credentials.GetUsername() + ":" + credentials.GetPassword()))
}

func NewAuthorizationBasicSecurityScheme(name string, credentials *HTTPBasicCredentials) (*SecurityScheme, error) {
	in := InHeader
	securityScheme, err := NewSecurityScheme(name, nil, HttpType, BasicScheme, &in, nil)
	if err != nil {
		return nil, err
	}

	if credentials != nil {
		err = securityScheme.SetValidValue(credentials)
		if err != nil {
			return nil, err
		}
	}

	return securityScheme, nil
}

func MustNewAuthorizationBasicSecurityScheme(name string, credentials *HTTPBasicCredentials) *SecurityScheme {
	securityScheme, err := NewAuthorizationBasicSecurityScheme(name, credentials)
	if err != nil {
		panic(err)
	}

	return securityScheme
}
