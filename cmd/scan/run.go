package scan

import (
	"errors"

	internalCmd "github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/x/telemetryx"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

func resolveSettings(cmd *cobra.Command) *internalCmd.ScanSettings {
	settings, err := internalCmd.ResolveScanSettings(cmd)
	if err != nil {
		telemetryx.Fatal(cmd, telemetryx.Reason(err, "invalid-configuration"))
	}
	return settings
}

// targetArg returns the positional argument, or the target of the
// configuration file when there is none.
func targetArg(cmd *cobra.Command, args []string, fromConfig func(settings *internalCmd.ScanSettings) string, settings *internalCmd.ScanSettings, kind string) string {
	if len(args) > 0 {
		return args[0]
	}
	if value := fromConfig(settings); value != "" {
		return value
	}
	telemetryx.Fatal(cmd, telemetryx.Reason(errors.New("a "+kind+" target is required, as an argument or in the configuration file"), "missing-target"))
	return ""
}

func executeScan(cmd *cobra.Command, s *scan.Scan, settings *internalCmd.ScanSettings) {
	ctx := cmd.Context()

	var bar *progressbar.ProgressBar
	if !settings.NoProgress {
		bar = internalCmd.NewProgressBar(len(s.GetOperationsScans()))
		defer func() { _ = bar.Finish() }()
	}
	reporter, _, err := s.Execute(ctx, func(operationScan *scan.OperationScan) {
		if bar != nil {
			_ = bar.Add(1)
		}
	})
	if err != nil {
		telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-executing-scenario"))
	}
	settings.PrintUnknownScans(cmd, s.UnknownScans)

	if err := internalCmd.WriteReport(ctx, cmd, reporter, settings); err != nil {
		telemetryx.Fatal(cmd, telemetryx.Reason(err, "error-printing-report"))
	}

	internalCmd.ExitIfFindings(cmd, reporter, settings.ScansFiltered(cmd))
}
