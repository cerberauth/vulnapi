package scan

import (
	"bufio"
	"log"
	"os"

	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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

func NewOpenAPIScanCmd() (scanCmd *cobra.Command) {
	scanCmd = &cobra.Command{
		Use:   "openapi [OpenAPIPAth]",
		Short: "Full OpenAPI operations scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/openapi")
			openapiUrlOrPath := args[0]

			var validToken *string
			if isStdinOpen() {
				stdin := readStdin()
				validToken = stdin
			}

			analyticsx.TrackEvent(ctx, tracer, "Scan OpenAPI", []attribute.KeyValue{})
			scan, err := scan.NewOpenAPIScan(openapiUrlOrPath, validToken, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			if reporter, _, err = scan.WithAllScans().Execute(); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}
		},
	}

	return scanCmd
}
