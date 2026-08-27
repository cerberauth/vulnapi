package serve

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewServeCmd() (serveCmd *cobra.Command) {
	serveCmd = &cobra.Command{
		Use:        "serve",
		Short:      "[DEPRECATED] The HTTP server has been removed",
		Deprecated: "the HTTP server was removed pending a proper redesign; see https://github.com/cerberauth/vulnapi/issues/303",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("vulnapi serve has been removed. It was not properly designed and is being rethought. Track progress at https://github.com/cerberauth/vulnapi/issues/303")
		},
	}

	return serveCmd
}
