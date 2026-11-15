package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/format"
	"github.com/cerberauth/reportx/transport"
	"github.com/cerberauth/vulnapi/config"
	"github.com/cerberauth/vulnapi/scan"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/cerberauth/x/reportx/harnessreport"
	"github.com/cerberauth/x/telemetryx"
	"github.com/getargvio/argvio-go"
	"github.com/spf13/cobra"
)

func isActive(f reportx.Finding) bool {
	return f.Status == "" || f.Status == reportx.StatusActive
}

func activeFindings(r *reportx.Report) int {
	n := 0
	for _, f := range r.Findings {
		if isActive(f) {
			n++
		}
	}
	return n
}

func highestCVSSScore(r *reportx.Report) float64 {
	var max float64
	for _, f := range r.Findings {
		if isActive(f) && f.CVSS40Score > max {
			max = f.CVSS40Score
		}
	}
	return max
}

var reportsCounter = argvio.NewCounter("report.written", argvio.Dims("format", "destination"))

var reportFormats = func() []string {
	names := make([]string, 0, len(format.FormatNames))
	for _, n := range format.FormatNames {
		names = append(names, string(n))
	}
	return names
}()

// recordReport counts the report by format and where it goes: stdout,
// a file (--output) and the --report-url endpoint, neither of which is sent.
func recordReport(ctx context.Context, cmd *cobra.Command, toURL bool) {
	f, _ := cmd.Flags().GetString("format")
	switch f {
	case "yml":
		f = string(format.FormatYAML)
	case "text", "plain":
		f = string(format.FormatTerminal)
	}
	f = telemetryx.Vocab(f, reportFormats...)
	destination := "stdout"
	if out, _ := cmd.Flags().GetString("output"); out != "" {
		destination = "file"
	}
	reportsCounter.Add(ctx, 1, f, destination)
	if toURL {
		reportsCounter.Add(ctx, 1, f, "http")
	}
}

// WriteReport formats and writes r according to the --format/--output/
// --report-url/--report-header flags registered via cobrareportx, and the
// report settings and suppressions of the configuration file.
func WriteReport(ctx context.Context, cmd *cobra.Command, r *reportx.Report, settings *ScanSettings) error {
	if r == nil {
		return errors.New("no report to write")
	}

	var cfg *config.Config
	if settings != nil {
		cfg = settings.Config
	}
	if cfg != nil {
		applySuppressions(cmd, r, cfg.Suppressions)
	}

	outputStream := os.Stdout
	if highestCVSSScore(r) >= GetSeverityThreshold() {
		outputStream = os.Stderr
	}

	var outputMessage string
	switch {
	case activeFindings(r) == 0:
		outputMessage = "Success: No issue detected!"
	case highestCVSSScore(r) >= 7.0:
		outputMessage = "Error: There are some high-risk issues. It's advised to take immediate action."
	default:
		outputMessage = "Warning: There are some issues. It's advised to take action."
	}

	fmt.Println()
	fmt.Fprintln(outputStream, outputMessage)

	sinks, cleanup, err := cobrareportx.SinksFromFlags(cmd)
	if err != nil {
		return err
	}
	defer cleanup()

	reportURL, _ := cmd.Flags().GetString("report-url")
	if cfg != nil && cfg.Report != nil {
		configSinks, configCleanup, err := configReportSinks(ctx, cmd, cfg.Report)
		defer configCleanup()
		if err != nil {
			return err
		}
		sinks = append(sinks, configSinks...)
		if reportURL == "" {
			reportURL = cfg.Report.URL
		}
	}

	if err := r.DeliverAll(ctx, sinks); err != nil {
		return err
	}

	recordReport(ctx, cmd, reportURL != "")
	return nil
}

func applySuppressions(cmd *cobra.Command, r *reportx.Report, suppressions []config.Suppression) {
	result := config.ApplySuppressions(r, suppressions, time.Now(), scan.MatchesScanID)
	for _, s := range result.Expired {
		target := s.Check
		if s.Operation != "" {
			target += " on " + s.Operation
		}
		cmd.PrintErrln("Warning: the suppression of " + target + " expired on " + s.Expires.Format(config.DateLayout) + ", its findings are reported again")
	}
	if result.Suppressed > 0 {
		cmd.PrintErrf("Info: %d finding(s) suppressed by the configuration file\n", result.Suppressed)
	}
}

func normalizeFormat(name string) string {
	switch name {
	case "yml":
		return string(format.FormatYAML)
	case "text", "plain":
		return string(format.FormatTerminal)
	}
	return name
}

func configReportSinks(ctx context.Context, cmd *cobra.Command, report *config.Report) ([]harnessreport.Sink, func(), error) {
	var sinks []harnessreport.Sink
	var files []*os.File
	cleanup := func() {
		for _, f := range files {
			_ = f.Close()
		}
	}
	for _, output := range report.Outputs {
		formatter, err := format.NewFormatter(normalizeFormat(output.Format))
		if err != nil {
			return nil, cleanup, err
		}
		file, err := os.Create(output.Path)
		if err != nil {
			return nil, cleanup, fmt.Errorf("report output: %w", err)
		}
		files = append(files, file)
		sinks = append(sinks, harnessreport.Sink{Formatter: formatter, Writer: file})
	}

	if report.URL != "" && !cmd.Flags().Changed("report-url") {
		reportFormat := report.Format
		if reportFormat == "" || cmd.Flags().Changed("report-format") {
			reportFormat, _ = cmd.Flags().GetString("report-format")
		}
		formatter, err := format.NewFormatter(normalizeFormat(reportFormat))
		if err != nil {
			return nil, cleanup, err
		}
		tr := transport.NewHTTPTransport(report.URL)
		tr.Headers = map[string]string{}
		for name, value := range report.Headers {
			resolved, err := value.Resolve(ctx)
			if err != nil {
				return nil, cleanup, fmt.Errorf("report.headers.%s: %w", name, err)
			}
			tr.Headers[name] = resolved
		}
		flagHeaders, _ := cmd.Flags().GetStringToString("report-header")
		for name, value := range flagHeaders {
			tr.Headers[name] = value
		}
		sinks = append(sinks, harnessreport.Sink{Formatter: formatter, Transport: tr})
	}
	return sinks, cleanup, nil
}

// ExitIfFindings exits cmd with status 1 if r has findings. When scansFiltered is
// true (the caller explicitly selected scans via --scans), any finding exits,
// ignoring the severity threshold. Otherwise, only findings meeting the
// severity threshold exit.
func ExitIfFindings(cmd *cobra.Command, r *reportx.Report, scansFiltered bool) {
	if scansFiltered {
		if activeFindings(r) > 0 {
			telemetryx.Exit(cmd, 1)
		}
		return
	}

	if highestCVSSScore(r) >= GetSeverityThreshold() {
		telemetryx.Exit(cmd, 1)
	}
}
