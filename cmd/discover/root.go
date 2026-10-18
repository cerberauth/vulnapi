package discover

import (
	"github.com/spf13/cobra"
)

func NewDiscoverCmd() (discoverCmd *cobra.Command) {
	discoverCmd = &cobra.Command{
		Use:   "discover [type]",
		Short: "Discover APIs, API endpoints and server information",
	}

	discoverCmd.AddCommand(NewDomainCmd())
	discoverCmd.AddCommand(NewAPICmd())

	return discoverCmd
}
