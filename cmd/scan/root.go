package scan

import (
	"github.com/spf13/cobra"
)

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "scan",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	return scanCmd
}
