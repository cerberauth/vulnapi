package auth

type SecuritySchemeValues struct {
	Default interface{}
	Values  map[string]interface{}
}

func NewSecuritySchemeValues() *SecuritySchemeValues {
	return NewSecuritySchemeValuesWithDefault(nil)
}

func NewSecuritySchemeValuesWithDefault(defaultValue interface{}) *SecuritySchemeValues {
	return &SecuritySchemeValues{
		Default: defaultValue,
		Values:  map[string]interface{}{},
	}
}
