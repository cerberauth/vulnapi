package scan_url

import (
	"github.com/cerberauth/vulnapi/scan"
	"github.com/spf13/cobra"
)

var (
	url string
	jwt string
)

func NewScanUrlCmd() (scanUrlCmd *cobra.Command) {
	scanUrlCmd = &cobra.Command{
		Use:   "scan-url",
		Short: "Scan against one URL",
		Run: func(cmd *cobra.Command, args []string) {
			errors, _ := scan.NewScan(url, jwt).WithNotVerifiedJwtScan().Execute()

			if len(errors) == 0 {
				println("Congratulations! No vulnerability has been discovered!")
			}

			for error := range errors {
				println(error)
			}
		},
	}

	scanUrlCmd.PersistentFlags().StringVarP(&url, "url", "u", "", "URL")
	scanUrlCmd.PersistentFlags().StringVarP(&jwt, "jwt", "j", "", "Valid JWT")

	return scanUrlCmd
}
