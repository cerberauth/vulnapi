package scan

import (
	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/harnessx"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scenario"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

func NewGraphQLScanCmd() (scanCmd *cobra.Command) {
	var allowUnsafeMethods bool

	scanCmd = &cobra.Command{
		Use:   "graphql [endpoint]",
		Short: "GraphQL scan",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			settings := resolveSettings(cmd)
			endpoint := targetArg(cmd, args, func(s *internalCmd.ScanSettings) string {
				if target := s.Target(); target != nil {
					return target.GraphQL
				}
				return ""
			}, settings, "GraphQL endpoint")

			req, err := cobracurl.BuildRequest(cmd, []string{endpoint})
			if err != nil {
				telemetryx.Fatal(cmd, err)
			}

			headers, err := settings.TargetHeaders(ctx, req.Header)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-configuration"))
			}
			client, err := internalCmd.NewHTTPClientFromCmd(cmd)
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-client"))
			}
			client = client.WithHeader(headers).WithCookies(req.Cookies())
			if _, err := internalCmd.ApplyAuthFlags(cmd, client); err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-auth-flags"))
			}
			request.SetDefaultClient(client)

			internalCmd.ApplyJWTFlags(cmd)

			s, err := scenario.NewGraphQLScan(harnessx.New(), req.URL, client, settings.ScanOptions())
			if err != nil {
				telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-scenario"))
			}
			executeScan(cmd, s, settings)
		},
	}

	cobracurl.RegisterFlags(scanCmd.Flags())

	scanCmd.Flags().StringArray("scans", nil, "Include specific scans")
	scanCmd.Flags().StringArray("exclude-scans", nil, "Exclude specific scans")
	internalCmd.AddJWTFlags(scanCmd)
	internalCmd.AddAuthFlags(scanCmd)
	cobrareportx.RegisterFormatFlags(scanCmd)
	cobrareportx.RegisterTransportFlags(scanCmd)
	scanCmd.Flags().Bool("no-progress", false, "Disable progress output")
	scanCmd.Flags().Float64("severity-threshold", 1, "Threshold to trigger stderr output if at least one vulnerability CVSS is higher")
	scanCmd.Flags().Bool("only-scans-above-threshold", false, "Only run checks that could reach --severity-threshold; exits on any finding since all of them do")
	internalCmd.RegisterAllowUnsafeMethodsFlag(scanCmd, &allowUnsafeMethods)

	return scanCmd
}
