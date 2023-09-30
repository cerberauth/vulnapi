package scan

import (
	"github.com/spf13/cobra"
)

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "API Scan",
		// Full API scan coming (not only one URL)
		Run: func(cmd *cobra.Command, args []string) {},
	}

	return scanCmd
}
