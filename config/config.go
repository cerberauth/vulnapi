package config

import (
	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

// AllSchemes is the identity scheme key whose credential applies to every
// security scheme without its own credential.
const AllSchemes = "*"

const SchemaURL = "https://schemas.cerberauth.com/vulnapi/config/v1.json"

type Config struct {
	Version      int                    `yaml:"version" json:"version"`
	Target       *Target                `yaml:"target,omitempty" json:"target,omitempty"`
	Identities   map[string]Identity    `yaml:"identities,omitempty" json:"identities,omitempty"`
	Scan         *Scan                  `yaml:"scan,omitempty" json:"scan,omitempty"`
	Report       *Report                `yaml:"report,omitempty" json:"report,omitempty"`
	Suppressions []Suppression          `yaml:"suppressions,omitempty" json:"suppressions,omitempty"`
	Environments map[string]Environment `yaml:"environments,omitempty" json:"environments,omitempty"`
	Enterprise   yaml.Node              `yaml:"enterprise,omitempty" json:"enterprise,omitempty"`

	path        string
	environment string
}

type Target struct {
	OpenAPI string           `yaml:"openapi,omitempty" json:"openapi,omitempty"`
	Server  string           `yaml:"server,omitempty" json:"server,omitempty"`
	GraphQL string           `yaml:"graphql,omitempty" json:"graphql,omitempty"`
	Request *Request         `yaml:"request,omitempty" json:"request,omitempty"`
	Headers map[string]Value `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type Request struct {
	URL    string `yaml:"url" json:"url"`
	Method string `yaml:"method,omitempty" json:"method,omitempty"`
	Data   string `yaml:"data,omitempty" json:"data,omitempty"`
}

type Identity struct {
	Role    string                `yaml:"role,omitempty" json:"role,omitempty"`
	Tenant  string                `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	Schemes map[string]Credential `yaml:"schemes" json:"schemes"`
}

type Credential struct {
	SecretRef `yaml:",inline" json:",inline"`
	OAuth2    *OAuth2 `yaml:"oauth2,omitempty" json:"oauth2,omitempty"`
}

type OAuth2 struct {
	TokenURL     string     `yaml:"tokenUrl,omitempty" json:"tokenUrl,omitempty"`
	ClientID     *SecretRef `yaml:"clientId" json:"clientId"`
	ClientSecret *SecretRef `yaml:"clientSecret,omitempty" json:"clientSecret,omitempty"`
	Username     *SecretRef `yaml:"username,omitempty" json:"username,omitempty"`
	Password     *SecretRef `yaml:"password,omitempty" json:"password,omitempty"`
	Scopes       []string   `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

type Scan struct {
	Checks             *Checks          `yaml:"checks,omitempty" json:"checks,omitempty"`
	Operations         *OperationFilter `yaml:"operations,omitempty" json:"operations,omitempty"`
	AllowUnsafeMethods *bool            `yaml:"allowUnsafeMethods,omitempty" json:"allowUnsafeMethods,omitempty"`
	Rate               string           `yaml:"rate,omitempty" json:"rate,omitempty"`
	Timeout            string           `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

type Checks struct {
	Include []string `yaml:"include,omitempty" json:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

type OperationFilter struct {
	Paths        []string `yaml:"paths,omitempty" json:"paths,omitempty"`
	ExcludePaths []string `yaml:"excludePaths,omitempty" json:"excludePaths,omitempty"`
	Tags         []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	OperationIDs []string `yaml:"operationIds,omitempty" json:"operationIds,omitempty"`
	Methods      []string `yaml:"methods,omitempty" json:"methods,omitempty"`
}

type Report struct {
	FailOn  string           `yaml:"failOn,omitempty" json:"failOn,omitempty"`
	Outputs []Output         `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	URL     string           `yaml:"url,omitempty" json:"url,omitempty"`
	Format  string           `yaml:"format,omitempty" json:"format,omitempty"`
	Headers map[string]Value `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type Output struct {
	Format string `yaml:"format" json:"format"`
	Path   string `yaml:"path" json:"path"`
}

type Suppression struct {
	Check     string `yaml:"check" json:"check"`
	Operation string `yaml:"operation,omitempty" json:"operation,omitempty"`
	Reason    string `yaml:"reason" json:"reason"`
	Expires   Date   `yaml:"expires" json:"expires"`
}

type Environment struct {
	Target     *Target             `yaml:"target,omitempty" json:"target,omitempty"`
	Identities map[string]Identity `yaml:"identities,omitempty" json:"identities,omitempty"`
	Scan       *Scan               `yaml:"scan,omitempty" json:"scan,omitempty"`
	Report     *Report             `yaml:"report,omitempty" json:"report,omitempty"`
}

func (c *Config) Path() string {
	return c.path
}

func (c *Config) EnvironmentName() string {
	return c.environment
}

func (c *Config) HasEnterprise() bool {
	return !c.Enterprise.IsZero()
}

func (c *Config) TargetKind() string {
	if c.Target == nil {
		return ""
	}
	switch {
	case c.Target.OpenAPI != "":
		return "openapi"
	case c.Target.GraphQL != "":
		return "graphql"
	case c.Target.Request != nil:
		return "curl"
	}
	return ""
}

// DefaultIdentity returns the identity used for a single-identity scan: the
// only one declared, or the one named "default".
func (c *Config) DefaultIdentity() (string, *Identity) {
	if len(c.Identities) == 1 {
		for name, identity := range c.Identities {
			return name, &identity
		}
	}
	if identity, ok := c.Identities["default"]; ok {
		return "default", &identity
	}
	return "", nil
}
