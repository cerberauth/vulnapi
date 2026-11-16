package scan

import (
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHarnessxReporter_ObservationsBecomeFindings(t *testing.T) {
	a := &harnessxReporter{checkDefs: map[harnessx.CheckID]checkdef.CheckDef{
		"jwt.alg_none": {ID: "jwt.alg_none", Name: "Alg None"},
	}}
	a.OnScanStart(harnessx.Target{URL: "http://localhost"}, 1)

	a.OnCheckComplete(harnessx.Result{CheckID: "jwt.alg_none", ResourceID: "op", Observations: []harnessx.Observation{
		{Evidence: "token-none"},
		{Evidence: "token-NONE"},
	}})
	a.OnCheckComplete(harnessx.Result{CheckID: "jwt.alg_none", ResourceID: "other"})

	require.Len(t, a.findings, 1)
	assert.Equal(t, "jwt.alg_none", a.findings[0].ID)
	assert.Equal(t, "token-none", a.findings[0].Parameter)
}

func TestCountFindings_Observations(t *testing.T) {
	n, ok := countFindings(harnessx.Result{Observations: []harnessx.Observation{{}, {}}})
	assert.True(t, ok)
	assert.Equal(t, 1, n)

	_, ok = countFindings(harnessx.Result{})
	assert.False(t, ok)
}
