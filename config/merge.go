package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}

// WithEnvironment returns the configuration with the named environment
// overlay applied on top of the file. An empty name returns c unchanged.
func (c *Config) WithEnvironment(name string) (*Config, error) {
	if name == "" {
		return c, nil
	}
	environment, ok := c.Environments[name]
	if !ok {
		available := sortedKeys(c.Environments)
		if len(available) == 0 {
			return nil, fmt.Errorf("environment %q not found: the configuration file defines no environments", name)
		}
		return nil, fmt.Errorf("environment %q not found, available: %s", name, strings.Join(available, ", "))
	}

	merged := *c
	merged.environment = name
	merged.Target = mergeTarget(c.Target, environment.Target)
	merged.Identities = mergeMap(c.Identities, environment.Identities)
	merged.Auth = mergeAuth(c.Auth, environment.Auth)
	merged.Scan = mergeScan(c.Scan, environment.Scan)
	merged.Report = mergeReport(c.Report, environment.Report)
	return &merged, nil
}

func mergeMap[V any](base, overlay map[string]V) map[string]V {
	if base == nil && overlay == nil {
		return nil
	}
	merged := maps.Clone(base)
	if merged == nil {
		merged = map[string]V{}
	}
	maps.Copy(merged, overlay)
	return merged
}

func override[T comparable](base, overlay T) T {
	var zero T
	if overlay != zero {
		return overlay
	}
	return base
}

func mergeTarget(base, overlay *Target) *Target {
	if overlay == nil {
		return base
	}
	if base == nil {
		return overlay
	}
	merged := *base
	if overlay.OpenAPI != "" || overlay.GraphQL != "" || overlay.Request != nil {
		merged.OpenAPI, merged.GraphQL, merged.Request = overlay.OpenAPI, overlay.GraphQL, overlay.Request
	}
	merged.Server = override(base.Server, overlay.Server)
	return &merged
}

func mergeScan(base, overlay *Scan) *Scan {
	if overlay == nil {
		return base
	}
	if base == nil {
		return overlay
	}
	merged := *base
	merged.Checks = override(base.Checks, overlay.Checks)
	merged.Operations = override(base.Operations, overlay.Operations)
	merged.AllowUnsafeMethods = override(base.AllowUnsafeMethods, overlay.AllowUnsafeMethods)
	merged.Rate = override(base.Rate, overlay.Rate)
	merged.Timeout = override(base.Timeout, overlay.Timeout)
	return &merged
}

func mergeReport(base, overlay *Report) *Report {
	if overlay == nil {
		return base
	}
	if base == nil {
		return overlay
	}
	merged := *base
	merged.FailOn = override(base.FailOn, overlay.FailOn)
	if overlay.Outputs != nil {
		merged.Outputs = overlay.Outputs
	}
	merged.URL = override(base.URL, overlay.URL)
	merged.Format = override(base.Format, overlay.Format)
	merged.Headers = mergeMap(base.Headers, overlay.Headers)
	return &merged
}

func mergeAuth(base, overlay *Auth) *Auth {
	if overlay == nil {
		return base
	}
	if base == nil {
		return overlay
	}
	merged := *base
	merged.ClientID = override(base.ClientID, overlay.ClientID)
	merged.ClientSecret = override(base.ClientSecret, overlay.ClientSecret)
	merged.TokenURL = override(base.TokenURL, overlay.TokenURL)
	if overlay.Scopes != nil {
		merged.Scopes = overlay.Scopes
	}
	merged.Username = override(base.Username, overlay.Username)
	merged.Password = override(base.Password, overlay.Password)
	merged.Login = override(base.Login, overlay.Login)
	merged.JWTPublicKey = override(base.JWTPublicKey, overlay.JWTPublicKey)
	return &merged
}
