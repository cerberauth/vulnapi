package printtable

import (
	"fmt"

	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan/discover/fingerprint"
	"github.com/olekukonko/tablewriter"
)

func FingerprintScanReport(reporter *report.Reporter) {
	report := reporter.GetReportByID(fingerprint.DiscoverFingerPrintScanID)
	if report == nil || !report.HasData() {
		return
	}

	data, ok := report.Data.(fingerprint.FingerPrintData)
	if !ok {
		return
	}

	rows := [][]string{}
	for _, fp := range data.AuthServices {
		rows = append(rows, []string{"Authentication Service", fp.Name})
	}

	for _, fp := range data.CDNs {
		rows = append(rows, []string{"CDN", fp.Name})
	}

	for _, fp := range data.Caching {
		rows = append(rows, []string{"Caching", fp.Name})
	}

	for _, fp := range data.CertificateAuthority {
		rows = append(rows, []string{"Certificate Authority", fp.Name})
	}

	for _, fp := range data.Databases {
		rows = append(rows, []string{"Database", fp.Name})
	}

	for _, fp := range data.Frameworks {
		rows = append(rows, []string{"Framework", fp.Name})
	}

	for _, fp := range data.Hosting {
		rows = append(rows, []string{"Hosting", fp.Name})
	}

	for _, fp := range data.Languages {
		rows = append(rows, []string{"Language", fp.Name})
	}

	for _, fp := range data.OS {
		rows = append(rows, []string{"Operating System", fp.Name})
	}

	for _, fp := range data.SecurityServices {
		rows = append(rows, []string{"Security Service", fp.Name})
	}

	for _, fp := range data.ServerExtensions {
		rows = append(rows, []string{"Server Extension", fp.Name})
	}

	for _, fp := range data.Servers {
		rows = append(rows, []string{"Server", fp.Name})
	}

	if len(rows) == 0 {
		return
	}

	fmt.Println()
	headers := []string{"Technologie/Service", "Value"}
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
