package scan

import (
	"bufio"
	"log"
	"os"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/openapi"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

var (
	securitySchemesValueArg map[string]string
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
		Short: "OpenAPI Operations Scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("scan/openapi")
			openapiUrlOrPath := args[0]

			openapi, err := openapi.LoadOpenAPI(ctx, openapiUrlOrPath)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			if err := openapi.Validate(ctx); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			var validToken *string
			if isStdinOpen() {
				validToken = readStdin()
			}

			values := make(map[string]interface{}, len(securitySchemesValueArg))
			for key, value := range securitySchemesValueArg {
				values[key] = &value
			}
			securitySchemesValues := auth.NewSecuritySchemeValues(values).WithDefault(validToken)

			analyticsx.TrackEvent(ctx, tracer, "Scan OpenAPI", []attribute.KeyValue{})
			client := NewHTTPClientFromArgs(rateLimit, proxy, headers, cookies)
			s, err := scenario.NewOpenAPIScan(openapi, securitySchemesValues, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			bar := NewProgressBar(len(s.GetOperationsScans()))
			if reporter, _, err = s.Execute(func(operationScan *scan.OperationScan) {
				bar.Add(1)
			}); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}
		},
	}

	AddCommonArgs(scanCmd)
	scanCmd.Flags().StringToStringVarP(&securitySchemesValueArg, "security-schemes", "", nil, "Example value for each security scheme")
	return scanCmd
}
