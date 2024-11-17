package auth

func NewAPIKeySecurityScheme(name string, in SchemeIn, value *string) (*SecurityScheme, error) {
	tokenFormat := NoneTokenFormat
	securityScheme, err := NewSecurityScheme(name, nil, ApiKey, NoneScheme, &in, &tokenFormat)
	if err != nil {
		return nil, err
	}

	if value != nil && *value != "" {
		err = securityScheme.SetValidValue(*value)
		if err != nil {
			return nil, err
		}
	}

	return securityScheme, nil
}

func MustNewAPIKeySecurityScheme(name string, in SchemeIn, value *string) *SecurityScheme {
	securityScheme, err := NewAPIKeySecurityScheme(name, in, value)
	if err != nil {
		panic(err)
	}

	return securityScheme
}
