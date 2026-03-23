package auth

import (
	jwtop "github.com/cerberauth/jwtop/jwt"
)

func NewAuthorizationBearerSecurityScheme(name string, value *string) (*SecurityScheme, error) {
	in := InHeader
	securityScheme, err := NewSecurityScheme(name, nil, HttpType, BearerScheme, &in, nil)
	if err != nil {
		return nil, err
	}

	if value != nil && *value != "" {
		err = securityScheme.SetValidValue(*value)
		if err != nil {
			return nil, err
		}

		var tokenFormat TokenFormat
		if jwtop.IsJWT(*value) {
			tokenFormat = JWTTokenFormat
		} else {
			tokenFormat = NoneTokenFormat
		}
		if err = securityScheme.SetTokenFormat(tokenFormat); err != nil {
			return nil, err
		}
	}

	return securityScheme, nil
}

func MustNewAuthorizationBearerSecurityScheme(name string, value *string) *SecurityScheme {
	securityScheme, err := NewAuthorizationBearerSecurityScheme(name, value)
	if err != nil {
		panic(err)
	}

	return securityScheme
}
