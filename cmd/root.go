package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cerberauth/vulnapi/cmd/discover"
	"github.com/cerberauth/vulnapi/cmd/jwt"
	"github.com/cerberauth/vulnapi/cmd/scan"
	"github.com/cerberauth/vulnapi/cmd/serve"
	"github.com/cerberauth/vulnapi/internal/analytics"
)

var sqaOptOut bool

func NewRootCmd(projectVersion string) (cmd *cobra.Command) {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of this application",
		Long:  `All software has versions. This is this application's`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(projectVersion)
		},
	}

	rootCmd := &cobra.Command{
		Use:   "vulnapi",
		Short: "vulnapi",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				ctx := cmd.Context()
				analytics.NewAnalytics(ctx, projectVersion)
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				analytics.Close()
			}
		},
	}
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(discover.NewDiscoverCmd())
	rootCmd.AddCommand(scan.NewScanCmd())
	rootCmd.AddCommand(jwt.NewJWTCmd())
	rootCmd.AddCommand(serve.NewServeCmd())

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

func Execute(projectVersion string) {
	c := NewRootCmd(projectVersion)

	if err := c.Execute(); err != nil {
		os.Exit(1)
	}
}
