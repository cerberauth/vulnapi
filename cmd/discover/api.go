package discover

import (
	"log"
	"net/http"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scenario"
	"github.com/cerberauth/x/analyticsx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func NewAPICmd() (apiCmd *cobra.Command) {
	apiCmd = &cobra.Command{
		Use:   "api [url]",
		Short: "Discover api endpoints and server information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			tracer := otel.Tracer("discover")
			baseUrl := args[0]

			analyticsx.TrackEvent(ctx, tracer, "Discover", []attribute.KeyValue{})
			client := internalCmd.NewHTTPClientFromArgs(internalCmd.GetRateLimit(), internalCmd.GetProxy(), internalCmd.GetHeaders(), internalCmd.GetCookies())
			s, err := scenario.NewDiscoverScan(http.MethodGet, baseUrl, client, nil)
			if err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}

			bar := internalCmd.NewProgressBar(len(s.GetOperationsScans()))
			if reporter, _, err = s.Execute(func(operationScan *scan.OperationScan) {
				bar.Add(1)
			}); err != nil {
				analyticsx.TrackError(ctx, tracer, err)
				log.Fatal(err)
			}
		},
	}

	internalCmd.AddCommonArgs(apiCmd)

	return apiCmd
}
