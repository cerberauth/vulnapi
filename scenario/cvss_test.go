package scenario

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
	discoverablegraphql "github.com/cerberauth/vulnapi/scan/discover/discoverable_graphql"
	discoverableopenapi "github.com/cerberauth/vulnapi/scan/discover/discoverable_openapi"
	exposedfiles "github.com/cerberauth/vulnapi/scan/discover/exposed_files"
	healthcheck "github.com/cerberauth/vulnapi/scan/discover/healthcheck"
	wellknown "github.com/cerberauth/vulnapi/scan/discover/well-known"
	introspectionenabled "github.com/cerberauth/vulnapi/scan/graphql/introspection_enabled"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allCheckDefs(t *testing.T) map[harnessx.CheckID]checkdef.CheckDef {
	t.Helper()
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	s, err := scan.NewScan(harnessx.New(), operation.Operations{op}, &scan.ScanOptions{})
	require.NoError(t, err)
	defs := WithAllCommonScans(s).CheckDefs()
	for _, def := range []checkdef.CheckDef{
		discoverableopenapi.Def, discoverablegraphql.Def, exposedfiles.Def, wellknown.Def, healthcheck.Def,
		introspectionenabled.Def,
	} {
		defs[harnessx.CheckID(def.ID)] = def
	}
	return defs
}

func TestCheckDefs_CVSSScoresMatchVectors(t *testing.T) {
	defs := allCheckDefs(t)
	require.NotEmpty(t, defs)
	for id, def := range defs {
		assert.NoError(t, def.ValidateCVSS(), id)
	}
}

var scanIDRowRe = regexp.MustCompile("^\\| `([^`]+)` \\|")

func expectedCVSSCell(defs map[harnessx.CheckID]checkdef.CheckDef, scanID string) (string, bool) {
	var scores []float64
	for id, def := range defs {
		if string(id) == scanID || strings.HasPrefix(string(id), scanID+"_") || slices.Contains(scan.LegacyCheckIDAliases(string(id)), scanID) {
			scores = append(scores, def.CVSSScore)
		}
	}
	if len(scores) == 0 {
		return "", false
	}
	lo, hi := slices.Min(scores), slices.Max(scores)
	if lo == hi {
		return fmt.Sprintf("%.1f", lo), true
	}
	return fmt.Sprintf("%.1f–%.1f", lo, hi), true
}

func TestScanIDsDocs_CVSSColumnMatchesCheckDefs(t *testing.T) {
	defs := allCheckDefs(t)
	for _, lang := range []string{"en", "fr"} {
		path := "../docs/" + lang + "/reference/scan-ids.mdx"
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		cvssColumn := -1
		for _, line := range strings.Split(string(content), "\n") {
			cells := strings.Split(strings.Trim(line, "|"), "|")
			if !strings.HasPrefix(line, "|") {
				cvssColumn = -1
				continue
			}
			if cvssColumn == -1 {
				cvssColumn = slices.IndexFunc(cells, func(c string) bool { return strings.TrimSpace(c) == "CVSS" })
				if cvssColumn == -1 {
					cvssColumn = -2
				}
				continue
			}
			m := scanIDRowRe.FindStringSubmatch(line)
			if cvssColumn < 0 || m == nil {
				continue
			}
			want, ok := expectedCVSSCell(defs, m[1])
			if assert.True(t, ok, "%s: no check definition for %s", path, m[1]) {
				assert.Equal(t, want, strings.TrimSpace(cells[cvssColumn]), "%s: %s", path, m[1])
			}
		}
	}
}
