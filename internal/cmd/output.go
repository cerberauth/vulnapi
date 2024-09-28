package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	printtable "github.com/cerberauth/vulnapi/internal/cmd/printtable"
	"github.com/cerberauth/vulnapi/report"
	"gopkg.in/yaml.v3"
)

func PrintOrExportReport(format string, transport string, report *report.Reporter) error {
	outputStream := os.Stdout
	if report.HasHigherThanSeverityThresholdVulnerability(GetSeverityThreshold()) {
		outputStream = os.Stderr
	}

	var outputMessage string
	if !report.HasVulnerability() {
		outputMessage = "Success: No vulnerabilities detected!"
	} else if report.HasHighRiskOrHigherSeverityVulnerability() {
		outputMessage = "Error: There are some high-risk issues. It's advised to take immediate action."
	} else {
		outputMessage = "Warning: There are some issues. It's advised to take action."
	}

	fmt.Println()
	fmt.Fprintln(outputStream, outputMessage)

	var output []byte
	var err error
	switch format {
	case "json":
		output, err = ExportJSON(report)
	case "yaml":
		output, err = ExportYAML(report)
	case "table":
		PrintTable(report)
	}

	if err != nil {
		return err
	}

	if output != nil && transport != "" {
		exportErr := exportWithTransport(transport, output)
		if exportErr != nil {
			return exportErr
		}
	}

	return nil
}

func PrintTable(report *report.Reporter) {
	printtable.WellKnownPathsScanReport(report)
	printtable.ContextualScanReport(report)
	printtable.DisplayReportTable(report)
}

func ExportJSON(report *report.Reporter) ([]byte, error) {
	reports := report.GetReports()
	return json.Marshal(reports)
}

func ExportYAML(report *report.Reporter) ([]byte, error) {
	reports := report.GetReports()
	return yaml.Marshal(reports)
}

func exportWithTransport(transport string, output []byte) error {
	switch transport {
	case "file":
		if outputPath == "" {
			return fmt.Errorf("output file is not specified")
		}
		return writeFile(outputPath, output)
	case "http":
		if outputURL == "" {
			return fmt.Errorf("output URL is not specified")
		}
		return sendHTTP(outputURL, output)
	}

	return nil
}

func writeFile(path string, output []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(output)
	if err != nil {
		return err
	}

	return nil
}

func sendHTTP(outputURL string, output []byte) error {
	return fmt.Errorf("HTTP transport not implemented")
}
