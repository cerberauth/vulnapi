package scenario

import (
	"net/http"
	"net/http/httptest"
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

// TestWithAllCommonScans_SharedOperationIsNotMutated runs every common check
// against one operation; run with -race to catch checks that write to the
// shared operation (e.g. through a shallow Clone).
func TestWithAllCommonScans_SharedOperationIsNotMutated(t *testing.T) {
	// Other methods return 405 so http_method_override tries its override
	// headers on cloned operations.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	op := operation.MustNewOperation(http.MethodGet, server.URL, nil, nil)
	op.Header.Set("X-Original", "value")
	s, err := scan.NewScan(harnessx.New(), operation.Operations{op}, &scan.ScanOptions{})
	require.NoError(t, err)
	WithAllCommonScans(s)

	_, _, err = s.Execute(t.Context(), nil)

	require.NoError(t, err)
	assert.Equal(t, http.Header{"X-Original": []string{"value"}}, op.Header)
}
