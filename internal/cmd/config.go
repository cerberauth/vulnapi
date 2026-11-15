package cmd

import (
	"errors"
	"os"

	"github.com/cerberauth/vulnapi/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func AddConfigFlags(flags *pflag.FlagSet) {
	flags.String("config", "", "Configuration file (default vulnapi.yaml or .vulnapi.yaml in the working directory, env "+config.PathEnv+")")
	flags.String("env", "", "Environment of the configuration file to apply (env "+config.EnvironmentEnv+")")
}

func flagOrEnv(cmd *cobra.Command, name, env string) string {
	if f := cmd.Flag(name); f != nil && f.Value.String() != "" {
		return f.Value.String()
	}
	return os.Getenv(env)
}

// LoadConfig loads the configuration file named by --config or
// VULNAPI_CONFIG, or found in the working directory, and applies the
// environment selected by --env or VULNAPI_ENV. It returns nil when there
// is no configuration file.
func LoadConfig(cmd *cobra.Command) (*config.Config, error) {
	c, err := FindConfig(cmd)
	if err == nil && c != nil && c.HasEnterprise() {
		cmd.PrintErrln("Info: the enterprise settings of " + c.Path() + " need the VulnAPI Enterprise build and are ignored")
	}
	return c, err
}

// FindConfig is LoadConfig without informational output.
func FindConfig(cmd *cobra.Command) (*config.Config, error) {
	path := flagOrEnv(cmd, "config", config.PathEnv)
	environment := flagOrEnv(cmd, "env", config.EnvironmentEnv)
	if path == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		if path, err = config.Discover(wd); err != nil {
			return nil, err
		}
	}
	if path == "" {
		if environment != "" {
			return nil, errors.New("--env requires a configuration file")
		}
		return nil, nil
	}

	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	return c.WithEnvironment(environment)
}
