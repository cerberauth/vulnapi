package auth

type SecuritySchemeValues struct {
	Default interface{}
	Values  map[string]interface{}
}

func NewSecuritySchemeValues(values map[string]interface{}) *SecuritySchemeValues {
	return &SecuritySchemeValues{
		Default: nil,
		Values:  values,
	}
}

func NewEmptySecuritySchemeValues() *SecuritySchemeValues {
	values := make(map[string]interface{})
	return NewSecuritySchemeValues(values)
}

func (s *SecuritySchemeValues) WithDefault(defaultValue interface{}) *SecuritySchemeValues {
	s.Default = defaultValue
	return s
}

func (s *SecuritySchemeValues) GetDefault() interface{} {
	return s.Default
}

func (s *SecuritySchemeValues) Get(key string) interface{} {
	if value, ok := s.Values[key]; ok {
		return value
	}
	return s.Default
}

func (s *SecuritySchemeValues) Set(key string, value interface{}) {
	s.Values[key] = value
}
