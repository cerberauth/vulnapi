package config

import (
	"errors"
	"fmt"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
)

var errNoConfig = errors.New("no configuration file found: pass --config or create vulnapi.yaml")

func NewConfigCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:          "config",
		Short:        "Validate and show the configuration file",
		SilenceUsage: true,
	}
	configCmd.AddCommand(newValidateCmd(), newShowCmd())
	return configCmd
}

func newValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate the configuration file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := internalCmd.LoadConfig(cmd)
			if err != nil {
				return err
			}
			if c == nil {
				return errNoConfig
			}
			message := c.Path() + " is valid"
			if c.EnvironmentName() != "" {
				message += fmt.Sprintf(" (environment %s)", c.EnvironmentName())
			}
			cmd.Println(message)
			return nil
		},
	}
}

func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show the effective configuration, with the selected environment applied and secrets masked",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := internalCmd.LoadConfig(cmd)
			if err != nil {
				return err
			}
			if c == nil {
				return errNoConfig
			}
			effective := *c
			if c.EnvironmentName() != "" {
				effective.Environments = nil
			}
			out, err := effective.MarshalMaskedYAML()
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
}
