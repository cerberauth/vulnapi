package auth

var defaultName = "no_auth"

func NewNoAuthSecurityScheme() (*SecurityScheme, error) {
	return NewSecurityScheme(defaultName, nil, None, NoneScheme, nil, nil)
}

func MustNewNoAuthSecurityScheme() *SecurityScheme {
	scheme, err := NewNoAuthSecurityScheme()
	if err != nil {
		panic(err)
	}

	return scheme
}
