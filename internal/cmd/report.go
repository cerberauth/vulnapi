package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/cerberauth/reportx"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/spf13/cobra"
)

func highestCVSSScore(r *reportx.Report) float64 {
	var max float64
	for _, f := range r.Findings {
		if f.CVSS40Score > max {
			max = f.CVSS40Score
		}
	}
	return max
}

// WriteReport formats and writes r according to the --format/--output/
// --report-url/--report-header flags registered via cobrareportx.
func WriteReport(ctx context.Context, cmd *cobra.Command, r *reportx.Report) error {
	outputStream := os.Stdout
	if highestCVSSScore(r) >= GetSeverityThreshold() {
		outputStream = os.Stderr
	}

	var outputMessage string
	switch {
	case len(r.Findings) == 0:
		outputMessage = "Success: No issue detected!"
	case highestCVSSScore(r) >= 7.0:
		outputMessage = "Error: There are some high-risk issues. It's advised to take immediate action."
	default:
		outputMessage = "Warning: There are some issues. It's advised to take action."
	}

	fmt.Println()
	fmt.Fprintln(outputStream, outputMessage)

	formatter, err := cobrareportx.FormatterFromFlags(cmd)
	if err != nil {
		return err
	}
	writer, cleanup, err := cobrareportx.WriterFromFlags(cmd)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := r.WriteTo(ctx, writer, formatter); err != nil {
		return err
	}

	httpTransport, err := cobrareportx.HTTPTransportFromFlags(cmd)
	if err != nil {
		return err
	}
	if httpTransport != nil {
		if err := r.Send(ctx, httpTransport, formatter); err != nil {
			return err
		}
	}

	return nil
}

// ExitIfFindings exits with status 1 if r has findings. When scansFiltered is
// true (the caller explicitly selected scans via --scans), any finding exits,
// ignoring the severity threshold. Otherwise, only findings meeting the
// severity threshold exit.
func ExitIfFindings(r *reportx.Report, scansFiltered bool) {
	if scansFiltered {
		if len(r.Findings) > 0 {
			os.Exit(1)
		}
		return
	}

	if highestCVSSScore(r) >= GetSeverityThreshold() {
		os.Exit(1)
	}
}
