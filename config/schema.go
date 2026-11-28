package config

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed schema/v1.json
var Schema []byte

// Masked returns the configuration with literal header values masked, for display.
func (c *Config) Masked() *Config {
	masked := *c
	masked.Target = maskTarget(c.Target)
	masked.Report = maskReport(c.Report)
	if c.Environments != nil {
		masked.Environments = make(map[string]Environment, len(c.Environments))
		for name, environment := range c.Environments {
			environment.Target = maskTarget(environment.Target)
			environment.Report = maskReport(environment.Report)
			masked.Environments[name] = environment
		}
	}
	return &masked
}

func maskHeaders(headers map[string]Value) map[string]Value {
	if headers == nil {
		return nil
	}
	masked := make(map[string]Value, len(headers))
	for name, value := range headers {
		if value.Ref == nil && value.Literal != "" {
			value.Literal = "****"
		}
		masked[name] = value
	}
	return masked
}

func maskTarget(t *Target) *Target {
	if t == nil {
		return nil
	}
	masked := *t
	masked.Headers = maskHeaders(t.Headers)
	return &masked
}

func maskReport(r *Report) *Report {
	if r == nil {
		return nil
	}
	masked := *r
	masked.Headers = maskHeaders(r.Headers)
	return &masked
}

func (c *Config) MarshalMaskedYAML() ([]byte, error) {
	return yaml.Marshal(c.Masked())
}
