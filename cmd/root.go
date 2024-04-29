package cmd

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cerberauth/vulnapi/cmd/jwt"
	"github.com/cerberauth/vulnapi/cmd/scan"
	"github.com/cerberauth/vulnapi/cmd/serve"
	"github.com/cerberauth/vulnapi/internal/analytics"
)

var sqaOptOut bool

func NewRootCmd() (cmd *cobra.Command) {
	rootCmd := &cobra.Command{
		Use:   "vulnapi",
		Short: "vulnapi",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				ctx := cmd.Context()
				analytics.NewAnalytics(ctx)
			}
		},
	}
	rootCmd.AddCommand(scan.NewScanCmd())
	rootCmd.AddCommand(jwt.NewRootCmd())
	rootCmd.AddCommand(serve.NewServeCmd())

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

func Execute() {
	c := NewRootCmd()

	if err := c.Execute(); err != nil {
		os.Exit(1)
	}
}
