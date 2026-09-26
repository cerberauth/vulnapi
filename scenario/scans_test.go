package scenario

import (
	"net/http"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithAllCommonScans_RegistersChecksNotInLegacyLinkTable(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	s, err := scan.NewScan(harnessx.New(), operation.Operations{op}, &scan.ScanOptions{})
	require.NoError(t, err)

	WithAllCommonScans(s)

	var ids []string
	for _, os := range s.GetOperationsScans() {
		ids = append(ids, os.CheckID)
	}
	assert.Contains(t, ids, "hmacconfusion")
	assert.Contains(t, ids, "jwkinjection")
	assert.Contains(t, ids, "psychicsig")
	// baseline is a genuine jwtop check too — every other jwtop check
	// depends on it — so it's registered directly like the rest, just
	// without a CheckDef, rather than hidden inside an internal wrapper.
	assert.Contains(t, ids, string(checkbase.CheckIDBaseline))
}

func TestWithAllCommonScans_LegacyExcludeScansStillExcludesRenamedCheck(t *testing.T) {
	op := operation.MustNewOperation(http.MethodGet, "http://localhost:8080/", nil, nil)
	s, err := scan.NewScan(harnessx.New(), operation.Operations{op}, &scan.ScanOptions{
		ExcludeScans: []string{"jwt.blank_secret"},
	})
	require.NoError(t, err)

	WithAllCommonScans(s)

	for _, os := range s.GetOperationsScans() {
		assert.NotEqual(t, string(blanksecret.Check.ID), os.CheckID)
	}
}
