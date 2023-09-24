package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cerberauth/vulnapi/cmd/scan"
)

func NewRootCmd() (cmd *cobra.Command) {
	var rootCmd = &cobra.Command{
		Use:   "vulnapi",
		Short: "vulnapi",
	}
	rootCmd.AddCommand(scan.NewScanCmd())

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute() {
	c := NewRootCmd()

	if err := c.Execute(); err != nil {
		os.Exit(1)
	}
}
