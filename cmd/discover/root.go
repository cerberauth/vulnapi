package discover

import (
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
)

const (
	otelName = "github.com/cerberauth/vulnapi/cmd/discover"

	otelErrorReasonAttributeKey = attribute.Key("error_reason")
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
