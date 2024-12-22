package printtable

import (
	"fmt"

	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	exposedfiles "github.com/cerberauth/vulnapi/scan/discover/exposed_files"
	wellknown "github.com/cerberauth/vulnapi/scan/discover/well-known"
	"github.com/olekukonko/tablewriter"
)

func wellKnownPathsFromReport(r *report.ScanReport, header string) [][]string {
	rows := [][]string{}
	if r == nil || !r.HasData() {
		return rows
	}

	data, ok := r.Data.(discover.DiscoverData)
	if ok && len(data) > 0 {
		rows = append(rows, []string{header, data[0].URL})
	}

	return rows
}

func WellKnownPathsScanReport(reporter *report.Reporter) {
	rows := [][]string{}

	openapiReport := reporter.GetScanReportByID(discoverableopenapi.DiscoverableOpenAPIScanID)
	rows = append(rows, wellKnownPathsFromReport(openapiReport, "OpenAPI")...)

	graphqlReport := reporter.GetScanReportByID(discoverablegraphql.DiscoverableGraphQLPathScanID)
	rows = append(rows, wellKnownPathsFromReport(graphqlReport, "GraphQL")...)

	wellKnownReport := reporter.GetScanReportByID(wellknown.DiscoverableWellKnownScanID)
	rows = append(rows, wellKnownPathsFromReport(wellKnownReport, "Well-Known")...)

	exposedFiles := reporter.GetScanReportByID(exposedfiles.DiscoverableFilesScanID)
	rows = append(rows, wellKnownPathsFromReport(exposedFiles, "Exposed Files")...)

	if len(rows) == 0 {
		return
	}

	fmt.Println()
	headers := []string{"Type", "URL"}
	table := CreateTable(headers)

	tableColors := make([]tablewriter.Colors, len(headers))
	tableColors[0] = tablewriter.Colors{tablewriter.Bold}
	tableColors[1] = tablewriter.Colors{tablewriter.Bold}

	for _, row := range rows {
		table.Rich(row, tableColors)
	}

	table.Render()
	fmt.Println()
}
