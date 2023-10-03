package scan

import (
	"bufio"
	"fmt"
	"log"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/spf13/cobra"
)

var (
	url string
	jwt string
)

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan [URL]",
		Short: "API Scan",
		// Full API scan coming (not only one URL)
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				url = args[0]
			}

			if jwt == "" {
				stdin, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				if err != nil {
					log.Fatal(fmt.Errorf("failed process input: %v", err))
				}
				jwt = stdin
			}

			reports, err := scan.NewScanner(url, &jwt).WithNotVerifiedJwtScan().WithAlgNoneJwtScan().Execute()
			if err != nil {
				log.Fatal(err)
			}

			if len(reports) == 0 {
				println("Congratulations! No vulnerability has been discovered!")
			}

			for _, report := range reports {
				log.Println(report)
			}
		},
	}

	scanCmd.PersistentFlags().StringVarP(&url, "url", "u", "", "URL")
	scanCmd.PersistentFlags().StringVarP(&jwt, "jwt", "j", "", "Valid JWT")

	return scanCmd
}
