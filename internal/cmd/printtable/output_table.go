package printtable

import (
	"fmt"
	"net/url"
	"os"
	"sort"

	"github.com/cerberauth/vulnapi/report"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	"github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	"github.com/olekukonko/tablewriter"
)

type ScanVulnerabilityReport struct {
	OperationMethod string `json:"method"`
	OperationPath   string `json:"path"`

	Vuln *report.VulnerabilityReport `json:"vuln"`
}

type SortByPathAndSeverity []*ScanVulnerabilityReport

func (a SortByPathAndSeverity) Len() int      { return len(a) }
func (a SortByPathAndSeverity) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a SortByPathAndSeverity) Less(i, j int) bool {
	if a[i].OperationPath == a[j].OperationPath {
		if a[i].OperationMethod == a[j].OperationMethod {
			return a[i].Vuln.Issue.CVSS.Score > a[j].Vuln.Issue.CVSS.Score
		}

		return a[i].OperationMethod < a[j].OperationMethod
	}

	return a[i].OperationPath < a[j].OperationPath
}

func NewScanVulnerabilityReports(report *report.Report) []*ScanVulnerabilityReport {
	reports := report.GetFailedVulnerabilityReports()
	vulns := make([]*ScanVulnerabilityReport, 0, len(reports))
	for _, vr := range reports {
		url, urlErr := url.Parse(report.Operation.URL)
		if urlErr != nil {
			continue
		}

		vulns = append(vulns, &ScanVulnerabilityReport{
			OperationMethod: report.Operation.Method,
			OperationPath:   url.Path,

			Vuln: vr,
		})
	}

	return vulns
}

func NewFullScanVulnerabilityReports(reports []*report.Report) []*ScanVulnerabilityReport {
	vulns := make([]*ScanVulnerabilityReport, 0)
	for _, r := range reports {
		vulns = append(vulns, NewScanVulnerabilityReports(r)...)
	}

	sort.Sort(SortByPathAndSeverity(vulns))

	return vulns
}

func severityTableColor(v *report.VulnerabilityReport) int {
	if v.IsLowRiskSeverity() || v.IsInfoRiskSeverity() {
		return tablewriter.BgBlueColor
	} else if v.IsMediumRiskSeverity() {
		return tablewriter.BgYellowColor
	} else if v.IsHighRiskSeverity() {
		return tablewriter.BgRedColor
	} else if v.IsCriticalRiskSeverity() {
		return tablewriter.BgHiRedColor
	}

	return tablewriter.BgWhiteColor
}

func WellKnownPathsScanReport(reporter *report.Reporter) {
	openapiURL := ""
	openapiReport := reporter.GetReportByID(discoverableopenapi.DiscoverableOpenAPIScanID)
	if openapiReport != nil && openapiReport.HasData() {
		openapiData, ok := openapiReport.Data.(discoverableopenapi.DiscoverableOpenAPIData)
		if ok {
			openapiURL = openapiData.URL
		}
	}

	graphqlURL := ""
	graphqlReport := reporter.GetReportByID(discoverablegraphql.DiscoverableGraphQLPathScanID)
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

func ContextualScanReport(reporter *report.Reporter) {
	report := reporter.GetReportByID(fingerprint.DiscoverFingerPrintScanID)
	if report == nil || !report.HasData() {
		return
	}

	data, ok := report.Data.(fingerprint.FingerPrintData)
	if !ok {
		return
	}

	fmt.Println()
	headers := []string{"Technologie/Service", "Value"}
	table := CreateTable(headers)

	tableColors := make([]tablewriter.Colors, len(headers))
	tableColors[0] = tablewriter.Colors{tablewriter.Bold}
	tableColors[1] = tablewriter.Colors{tablewriter.Bold}

	for _, fp := range data.AuthServices {
		table.Rich([]string{"Authentication Service", fp.Name}, tableColors)
	}

	for _, fp := range data.CDNs {
		table.Rich([]string{"CDN", fp.Name}, tableColors)
	}

	for _, fp := range data.Caching {
		table.Rich([]string{"Caching", fp.Name}, tableColors)
	}

	for _, fp := range data.CertificateAuthority {
		table.Rich([]string{"Certificate Authority", fp.Name}, tableColors)
	}

	for _, fp := range data.Databases {
		table.Rich([]string{"Database", fp.Name}, tableColors)
	}

	for _, fp := range data.Frameworks {
		table.Rich([]string{"Framework", fp.Name}, tableColors)
	}

	for _, fp := range data.Hosting {
		table.Rich([]string{"Hosting", fp.Name}, tableColors)
	}

	for _, fp := range data.Languages {
		table.Rich([]string{"Language", fp.Name}, tableColors)
	}

	for _, fp := range data.OS {
		table.Rich([]string{"Operating System", fp.Name}, tableColors)
	}

	for _, fp := range data.SecurityServices {
		table.Rich([]string{"Security Service", fp.Name}, tableColors)
	}

	for _, fp := range data.ServerExtensions {
		table.Rich([]string{"Server Extension", fp.Name}, tableColors)
	}

	for _, fp := range data.Servers {
		table.Rich([]string{"Server", fp.Name}, tableColors)
	}

	table.Render()
	fmt.Println()
}

func DisplayReportTable(reporter *report.Reporter) {
	if reporter == nil || len(reporter.GetReports()) == 0 {
		return
	}

	headers := []string{"Operation", "Risk Level", "CVSS 4.0 Score", "OWASP", "Vulnerability"}
	table := CreateTable(headers)

	vulnerabilityReports := NewFullScanVulnerabilityReports(reporter.GetReports())
	for _, vulnReport := range vulnerabilityReports {
		row := []string{
			fmt.Sprintf("%s %s", vulnReport.OperationMethod, vulnReport.OperationPath),
			vulnReport.Vuln.SeverityLevelString(),
			fmt.Sprintf("%.1f", vulnReport.Vuln.Issue.CVSS.Score),
			string(vulnReport.Vuln.Classifications.OWASP),
			vulnReport.Vuln.Name,
		}

		tableColors := make([]tablewriter.Colors, len(headers))
		for i := range tableColors {
			if i == 1 {
				tableColors[i] = tablewriter.Colors{tablewriter.Bold, severityTableColor(vulnReport.Vuln)}
			} else {
				tableColors[i] = tablewriter.Colors{}
			}
		}

		table.Rich(row, tableColors)
	}

	errors := reporter.GetErrors()
	if len(errors) > 0 {
		fmt.Println()
		fmt.Println("Errors:")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
	}

	table.Render()
	fmt.Println()
}

func CreateTable(headers []string) *tablewriter.Table {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(headers)
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.SetAutoMergeCellsByColumnIndex([]int{0})

	return table
}

func DisplayUnexpectedErrorMessage() {
	fmt.Println()
	fmt.Println("If you think that report is not accurate or if you have any suggestions for improvements, please open an issue at: https://github.com/cerberauth/vulnapi/issues/new.")
}
