package scan

import (
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
)

const (
	otelName = "github.com/cerberauth/vulnapi/cmd/scan"

	otelErrorReasonAttributeKey = attribute.Key("error_reason")
	includeScansAttributeKey    = attribute.Key("include_scans")
	excludeScansAttributeKey    = attribute.Key("exclude_scans")
)

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan [type]",
		Short: "API Scan",
	}

	scanCmd.AddCommand(NewCURLScanCmd())
	scanCmd.AddCommand(NewOpenAPIScanCmd())
	scanCmd.AddCommand(NewGraphQLScanCmd())

	return scanCmd
}
