package scan

import (
	"github.com/spf13/cobra"
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
