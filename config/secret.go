package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrLiteralSecret = errors.New("secrets must be a reference ({env: NAME}, {file: PATH} or {command: CMD}), not a literal value")

type SecretRef struct {
	Env     string `yaml:"env,omitempty" json:"env,omitempty"`
	File    string `yaml:"file,omitempty" json:"file,omitempty"`
	Command string `yaml:"command,omitempty" json:"command,omitempty"`

	literal bool
}

type secretRefFields struct {
	Env     string `yaml:"env,omitempty"`
	File    string `yaml:"file,omitempty"`
	Command string `yaml:"command,omitempty"`
}

func (s *SecretRef) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*s = SecretRef{literal: true}
		return nil
	}
	var fields secretRefFields
	if err := decodeStrict(node, &fields); err != nil {
		return err
	}
	*s = SecretRef{Env: fields.Env, File: fields.File, Command: fields.Command}
	return nil
}

func (s SecretRef) IsZero() bool {
	return s.Env == "" && s.File == "" && s.Command == "" && !s.literal
}

func (s SecretRef) count() int {
	n := 0
	for _, v := range []string{s.Env, s.File, s.Command} {
		if v != "" {
			n++
		}
	}
	return n
}

func (s SecretRef) validate() error {
	if s.literal {
		return ErrLiteralSecret
	}
	if s.count() != 1 {
		return errors.New("exactly one of env, file or command is required")
	}
	return nil
}

func (s SecretRef) String() string {
	switch {
	case s.Env != "":
		return "env:" + s.Env
	case s.File != "":
		return "file:" + s.File
	case s.Command != "":
		return "command:" + s.Command
	}
	return ""
}

func (s SecretRef) Resolve(ctx context.Context) (string, error) {
	switch {
	case s.literal:
		return "", ErrLiteralSecret
	case s.Env != "":
		value, ok := os.LookupEnv(s.Env)
		if !ok {
			return "", fmt.Errorf("environment variable %s is not set", s.Env)
		}
		return value, nil
	case s.File != "":
		content, err := os.ReadFile(s.File)
		if err != nil {
			return "", fmt.Errorf("reading secret file: %w", err)
		}
		return strings.TrimRight(string(content), "\r\n"), nil
	case s.Command != "":
		var stdout bytes.Buffer
		cmd := exec.CommandContext(ctx, "sh", "-c", s.Command) //nolint:gosec
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("secret command: %w", err)
		}
		return strings.TrimSpace(stdout.String()), nil
	}
	return "", errors.New("empty secret reference")
}

func (s *SecretRef) resolvePaths(dir string) {
	if s != nil && s.File != "" && !filepath.IsAbs(s.File) {
		s.File = filepath.Join(dir, s.File)
	}
}

// Value is a plain string or a secret reference, for settings such as HTTP
// headers that are not always secret.
type Value struct {
	Literal string
	Ref     *SecretRef
}

func (v *Value) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		*v = Value{Literal: node.Value}
		return nil
	}
	var ref SecretRef
	if err := node.Decode(&ref); err != nil {
		return err
	}
	*v = Value{Ref: &ref}
	return nil
}

func (v Value) MarshalYAML() (interface{}, error) {
	if v.Ref != nil {
		return v.Ref, nil
	}
	return v.Literal, nil
}

func (v Value) Resolve(ctx context.Context) (string, error) {
	if v.Ref != nil {
		return v.Ref.Resolve(ctx)
	}
	return v.Literal, nil
}

func (v Value) validate() error {
	if v.Ref != nil {
		return v.Ref.validate()
	}
	return nil
}
