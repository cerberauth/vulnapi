package printtable

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
)

func CreateTable(headers []string) *tablewriter.Table {
	table := tablewriter.NewTable(os.Stdout,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Borders: tw.Border{
				Left:  tw.On,
				Right: tw.On,
			},
			Settings: tw.Settings{
				Separators: tw.Separators{
					BetweenColumns: tw.On,
				},
			},
		})),
		tablewriter.WithConfig(tablewriter.Config{
			Header: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignLeft},
			},
			Row: tw.CellConfig{
				Alignment: tw.CellAlignment{Global: tw.AlignLeft},
				Merging: tw.CellMerging{
					Mode:          tw.MergeHorizontal,
					ByColumnIndex: tw.NewBoolMapper(0),
				},
			},
		}),
	)

	// Convert headers to []any for the new API
	headerAny := make([]any, len(headers))
	for i, h := range headers {
		headerAny[i] = h
	}
	table.Header(headerAny...)

	return table
}

func DisplayUnexpectedErrorMessage() {
	fmt.Println()
	fmt.Println("If you think that report is not accurate or if you have any suggestions for improvements, please open an issue at: https://github.com/cerberauth/vulnapi/issues/new.")
}
