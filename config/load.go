package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	PathEnv        = "VULNAPI_CONFIG"
	EnvironmentEnv = "VULNAPI_ENV"
)

var DefaultFileNames = []string{"vulnapi.yaml", ".vulnapi.yaml"}

// Discover returns the configuration file found in dir, or "" when there is none.
func Discover(dir string) (string, error) {
	for _, name := range DefaultFileNames {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err == nil && !info.IsDir() {
			return path, nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return "", nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("reading configuration file: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data, filepath.Dir(absPath))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	return c, nil
}

// Parse decodes a configuration file. Relative paths in it are resolved
// against dir, the directory of the file.
func Parse(data []byte, dir string) (*Config, error) {
	var c Config
	if err := decodeStrictBytes(data, &c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty configuration file")
		}
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	c.resolvePaths(dir)
	return &c, nil
}

func decodeStrictBytes(data []byte, out interface{}) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(out)
}

func decodeStrict(node *yaml.Node, out interface{}) error {
	data, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	if err := decodeStrictBytes(data, out); err != nil {
		return fmt.Errorf("line %d: %w", node.Line, err)
	}
	return nil
}

func (c *Config) resolvePaths(dir string) {
	c.Target.resolvePaths(dir)
	for name, identity := range c.Identities {
		identity.resolvePaths(dir)
		c.Identities[name] = identity
	}
	c.Report.resolvePaths(dir)
	for name, environment := range c.Environments {
		environment.Target.resolvePaths(dir)
		for identityName, identity := range environment.Identities {
			identity.resolvePaths(dir)
			environment.Identities[identityName] = identity
		}
		environment.Report.resolvePaths(dir)
		c.Environments[name] = environment
	}
}

func isURL(location string) bool {
	return len(location) > 7 && (location[:7] == "http://" || (len(location) > 8 && location[:8] == "https://"))
}

func (t *Target) resolvePaths(dir string) {
	if t == nil {
		return
	}
	if t.OpenAPI != "" && !isURL(t.OpenAPI) && !filepath.IsAbs(t.OpenAPI) {
		t.OpenAPI = filepath.Join(dir, t.OpenAPI)
	}
	for name, header := range t.Headers {
		header.Ref.resolvePaths(dir)
		t.Headers[name] = header
	}
}

func (i *Identity) resolvePaths(dir string) {
	for name, credential := range i.Schemes {
		credential.resolvePaths(dir)
		if credential.OAuth2 != nil {
			for _, ref := range credential.OAuth2.refs() {
				ref.resolvePaths(dir)
			}
		}
		i.Schemes[name] = credential
	}
}

func (r *Report) resolvePaths(dir string) {
	if r == nil {
		return
	}
	for i, output := range r.Outputs {
		if output.Path != "" && !filepath.IsAbs(output.Path) {
			r.Outputs[i].Path = filepath.Join(dir, output.Path)
		}
	}
	for name, header := range r.Headers {
		header.Ref.resolvePaths(dir)
		r.Headers[name] = header
	}
}

func (o *OAuth2) refs() []*SecretRef {
	var refs []*SecretRef
	for _, ref := range []*SecretRef{o.ClientID, o.ClientSecret, o.Username, o.Password} {
		if ref != nil {
			refs = append(refs, ref)
		}
	}
	return refs
}

func (c *Credential) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*c = Credential{SecretRef: SecretRef{literal: true}}
		return nil
	}
	var fields struct {
		Env     string  `yaml:"env,omitempty"`
		File    string  `yaml:"file,omitempty"`
		Command string  `yaml:"command,omitempty"`
		OAuth2  *OAuth2 `yaml:"oauth2,omitempty"`
	}
	if err := decodeStrict(node, &fields); err != nil {
		return err
	}
	*c = Credential{SecretRef: SecretRef{Env: fields.Env, File: fields.File, Command: fields.Command}, OAuth2: fields.OAuth2}
	return nil
}

func (c Credential) MarshalYAML() (interface{}, error) {
	type credential struct {
		Env     string  `yaml:"env,omitempty"`
		File    string  `yaml:"file,omitempty"`
		Command string  `yaml:"command,omitempty"`
		OAuth2  *OAuth2 `yaml:"oauth2,omitempty"`
	}
	return credential{Env: c.Env, File: c.File, Command: c.Command, OAuth2: c.OAuth2}, nil
}

const DateLayout = "2006-01-02"

type Date struct {
	time.Time
}

func (d *Date) UnmarshalYAML(node *yaml.Node) error {
	t, err := time.Parse(DateLayout, node.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid date %q, expected YYYY-MM-DD", node.Line, node.Value)
	}
	d.Time = t
	return nil
}

func (d Date) MarshalYAML() (interface{}, error) {
	if d.IsZero() {
		return "", nil
	}
	return d.Format(DateLayout), nil
}
