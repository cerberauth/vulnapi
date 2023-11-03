package scan

import (
	"bufio"
	"log"
	"os"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/spf13/cobra"
)

var (
	openapiUrlOrPath string
	url              string
)

func isStdinOpen() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func readStdin() *string {
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		t := scanner.Text()
		return &t
	}

	return nil
}

func NewScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "scan [URL]",
		Short: "API Scan",
		// Full API scan coming (not only one URL)
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				url = args[0]
			}

			opts := scan.ScanOptions{
				Url:              url,
				OpenAPIUrlOrPath: openapiUrlOrPath,
			}
			scanner, err := scan.NewScanner(opts)
			if err != nil {
				log.Fatal(err)
			}

			if isStdinOpen() {
				stdin := readStdin()
				if stdin != nil {
					bearerSecurityScheme := auth.NewAuthorizationBearerSecurityScheme("default", stdin)
					scanner.AddSecurityScheme(bearerSecurityScheme)
				}
			}

			rpr, _, err := scanner.WithAllScans().Execute()
			if err != nil {
				log.Fatal(err)
			}

			if !rpr.HasVulnerability() {
				log.Println("Congratulations! No vulnerability has been discovered!")
			}

			for _, r := range rpr.GetVulnerabilityReports() {
				log.Println(r)
			}
		},
	}

	scanCmd.PersistentFlags().StringVarP(&openapiUrlOrPath, "openapi", "", "", "OpenAPI URL or Path. The scan will be performed against the operations listed in OpenAPI file.")
	scanCmd.PersistentFlags().StringVarP(&url, "url", "u", "", "URL")

	return scanCmd
}
