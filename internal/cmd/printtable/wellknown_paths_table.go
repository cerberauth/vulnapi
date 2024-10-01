package printtable

import (
	"fmt"

	"github.com/cerberauth/vulnapi/report"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	"github.com/olekukonko/tablewriter"
)

func WellKnownPathsScanReport(reporter *report.Reporter) {
	openapiURL := ""
	openapiReport := reporter.GetScanReportByID(discoverableopenapi.DiscoverableOpenAPIScanID)
	if openapiReport != nil && openapiReport.HasData() {
		openapiData, ok := openapiReport.Data.(discoverableopenapi.DiscoverableOpenAPIData)
		if ok {
			openapiURL = openapiData.URL
		}
	}

	graphqlURL := ""
	graphqlReport := reporter.GetScanReportByID(discoverablegraphql.DiscoverableGraphQLPathScanID)
	if graphqlReport != nil && graphqlReport.HasData() {
		graphqlData, ok := graphqlReport.Data.(discoverablegraphql.DiscoverableGraphQLPathData)
		if ok {
			graphqlURL = graphqlData.URL
		}
	}

	if openapiURL == "" && graphqlURL == "" {
		fmt.Println("No well-known paths were found.")
		return
	}

	fmt.Println()
	headers := []string{"Well-Known Paths", "URL"}
	table := CreateTable(headers)

	tableColors := make([]tablewriter.Colors, len(headers))
	tableColors[0] = tablewriter.Colors{tablewriter.Bold}
	tableColors[1] = tablewriter.Colors{tablewriter.Bold}

	if openapiURL != "" {
		table.Rich([]string{"OpenAPI", openapiURL}, tableColors)
	}
	if graphqlURL != "" {
		table.Rich([]string{"GraphQL", graphqlURL}, tableColors)
	}

	table.Render()
	fmt.Println()
}
