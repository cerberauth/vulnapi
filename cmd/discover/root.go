package discover

import (
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/report"
	"github.com/spf13/cobra"
)

var reporter *report.Reporter

func NewDiscoverCmd() (discoverCmd *cobra.Command) {
	discoverCmd = &cobra.Command{
		Use:   "discover [type]",
		Short: "Discover APIs, API endpoints and server information",
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if reporter == nil {
				return
			}

			internalCmd.WellKnownPathsScanReport(reporter)
			internalCmd.ContextualScanReport(reporter)
		},
	}

	discoverCmd.AddCommand(NewAPICmd())

	return discoverCmd
}
