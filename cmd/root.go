package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cerberauth/vulnapi/cmd/jwt"
	"github.com/cerberauth/vulnapi/cmd/scan"
)

func NewRootCmd() (cmd *cobra.Command) {
	rootCmd := &cobra.Command{
		Use:   "vulnapi",
		Short: "vulnapi",
	}
	rootCmd.AddCommand(scan.NewScanCmd())
	rootCmd.AddCommand(jwt.NewRootCmd())

	return rootCmd
}

func Execute() {
	c := NewRootCmd()

	if err := c.Execute(); err != nil {
		os.Exit(1)
	}
}
