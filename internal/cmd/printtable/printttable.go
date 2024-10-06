package printtable

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
)

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
