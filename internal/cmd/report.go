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
	if report.HasHigherThanSeverityThresholdIssue(GetSeverityThreshold()) {
		outputStream = os.Stderr
	}

	var outputMessage string
	switch {
	case !report.HasIssue():
		outputMessage = "Success: No issue detected!"
	case report.HasHighRiskOrHigherSeverityIssue():
		outputMessage = "Error: There are some high-risk issues. It's advised to take immediate action."
	default:
		outputMessage = "Warning: There are some issues. It's advised to take action."
	}

	fmt.Println()
	fmt.Fprintln(outputStream, outputMessage)

	var output []byte
	var err error
	threshold := GetSeverityThreshold()
	switch format {
	case "json":
		output, err = ExportJSONWithThreshold(report, threshold)
	case "yaml":
		output, err = ExportYAMLWithThreshold(report, threshold)
	case "table":
		PrintTableWithThreshold(report, threshold)
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
	printtable.FingerprintScanReport(report)
	printtable.DisplayReportSummaryTable(report)
	printtable.DisplayReportTable(report)
}

func PrintTableWithThreshold(report *report.Reporter, threshold float64) {
	printtable.WellKnownPathsScanReport(report)
	printtable.FingerprintScanReport(report)
	printtable.DisplayReportSummaryTable(report)
	printtable.DisplayReportTableWithThreshold(report, threshold)
}

func ExportJSON(report *report.Reporter) ([]byte, error) {
	return json.Marshal(report)
}

func ExportJSONWithThreshold(report *report.Reporter, threshold float64) ([]byte, error) {
	filteredReporter := createFilteredReporter(report, threshold)
	return json.Marshal(filteredReporter)
}

func ExportYAML(report *report.Reporter) ([]byte, error) {
	return yaml.Marshal(report)
}

func ExportYAMLWithThreshold(report *report.Reporter, threshold float64) ([]byte, error) {
	filteredReporter := createFilteredReporter(report, threshold)
	return yaml.Marshal(filteredReporter)
}

// createFilteredReporter creates a copy of the reporter with only scan reports that meet the severity threshold
func createFilteredReporter(original *report.Reporter, threshold float64) *report.Reporter {
	filteredReporter := &report.Reporter{
		Schema:      original.Schema,
		Options:     original.Options,
		Curl:        original.Curl,
		OpenAPI:     original.OpenAPI,
		GraphQL:     original.GraphQL,
		ScanReports: original.GetFilteredScanReports(threshold),
	}
	return filteredReporter
}

func exportWithTransport(transport string, output []byte) error {
	switch transport {
	case "file":
		if reportFile == "" {
			return fmt.Errorf("output file is not specified")
		}
		return writeFile(reportFile, output)
	case "http":
		if reportURL == "" {
			return fmt.Errorf("output URL is not specified")
		}
		return sendHTTP(reportURL, output)
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
