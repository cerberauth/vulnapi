package mcpserver

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// DefaultEnvPrefix is the prefix an environment variable name must have to be
// referenced from a tool call, unless it is listed with --allow-env.
const DefaultEnvPrefix = "VULNAPI_"

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EnvResolver resolves credentials passed by reference: a tool call names an
// environment variable and the server reads its value. Credentials never
// travel through tool arguments, and the variables a tool call may name are
// limited so an agent cannot read arbitrary environment variables.
type EnvResolver struct {
	allowed []string
	lookup  func(string) (string, bool)
}

// NewEnvResolver returns a resolver accepting names starting with
// DefaultEnvPrefix and the names in allowed. An allowed entry ending in "*"
// is a prefix.
func NewEnvResolver(allowed []string) *EnvResolver {
	return &EnvResolver{allowed: allowed, lookup: os.LookupEnv}
}

func (r *EnvResolver) permitted(name string) bool {
	if strings.HasPrefix(name, DefaultEnvPrefix) {
		return true
	}
	for _, entry := range r.allowed {
		if prefix, ok := strings.CutSuffix(entry, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if name == entry {
			return true
		}
	}
	return false
}

// Resolve returns the value of the environment variable name.
func (r *EnvResolver) Resolve(name string) (string, error) {
	if !envNamePattern.MatchString(name) {
		return "", fmt.Errorf("%q is not an environment variable name: pass the name of the variable holding the credential, never the credential itself", name)
	}
	if !r.permitted(name) {
		return "", fmt.Errorf("environment variable %s is not available to tool calls: its name must start with %s or be listed with --allow-env", name, DefaultEnvPrefix)
	}
	value, ok := r.lookup(name)
	if !ok || value == "" {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	return value, nil
}
