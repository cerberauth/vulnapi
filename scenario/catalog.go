package scenario

import (
	"net/http"
	"slices"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/scan"
)

// CheckCatalog returns the definition of every check any scenario can run
// (common, GraphQL and discovery checks), sorted by ID. It builds the
// scenarios offline, without sending a request.
func CheckCatalog() ([]checkdef.CheckDef, error) {
	op, err := operation.NewOperation(http.MethodGet, "http://localhost/", nil, request.NewClient(request.NewClientOptions{}))
	if err != nil {
		return nil, err
	}

	byID := map[string]checkdef.CheckDef{}
	for _, register := range []func(*scan.Scan) *scan.Scan{WithGraphQLScans, WithDiscoverScans} {
		s, err := scan.NewScan(harnessx.New(), operation.Operations{op}, nil)
		if err != nil {
			return nil, err
		}
		for _, def := range register(s).CheckDefs() {
			byID[def.ID] = def
		}
	}

	defs := make([]checkdef.CheckDef, 0, len(byID))
	for _, def := range byID {
		defs = append(defs, def)
	}
	slices.SortFunc(defs, func(a, b checkdef.CheckDef) int { return strings.Compare(a.ID, b.ID) })
	return defs, nil
}
