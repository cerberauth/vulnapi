package scan

import (
	"io"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/harnessx"
	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scenario"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

func applyConfigRequest(cmd *cobra.Command, settings *internalCmd.ScanSettings) string {
	target := settings.Target()
	if target == nil || target.Request == nil {
		return ""
	}
	if target.Request.Method != "" && !cmd.Flags().Changed("request") {
		_ = cmd.Flags().Set("request", target.Request.Method)
	}
	if target.Request.Data != "" && !cmd.Flags().Changed("data") {
		_ = cmd.Flags().Set("data", target.Request.Data)
	}
	return target.Request.URL
}

func NewCURLScanCmd() (scanCmd *cobra.Command) {
	var allowUnsafeMethods bool

	scanCmd = &cobra.Command{
		Use:   "curl [URL]",
		Short: "CURL style Scan",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ctx := cmd.Context()
			settings := resolveSettings(cmd)
			url := targetArg(cmd, args, func(s *internalCmd.ScanSettings) string { return applyConfigRequest(cmd, s) }, settings, "URL")

			req, err := cobracurl.BuildRequest(cmd, []string{url})
			if err != nil {
				telemetryx.Fatal(cmd, err)
			}

			var curlData string
			if req.Body != nil {
				bodyBytes, readErr := io.ReadAll(req.Body)
				if readErr != nil {
					telemetryx.Fatal(cmd, telemetryx.Reason(readErr, "error-reading-body"))
				}
				curlData = string(bodyBytes)
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

			s, err := scenario.NewURLScan(harnessx.New(), req.Method, req.URL, curlData, client, settings.ScanOptions())
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
