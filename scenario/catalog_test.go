package scenario_test

import (
	"strings"
	"testing"

	"github.com/cerberauth/vulnapi/scenario"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckCatalog(t *testing.T) {
	defs, err := scenario.CheckCatalog()
	require.NoError(t, err)
	require.NotEmpty(t, defs)

	ids := map[string]bool{}
	previous := ""
	for _, def := range defs {
		assert.NotEmpty(t, def.ID)
		assert.NotEmpty(t, def.Name, def.ID)
		assert.False(t, strings.HasPrefix(def.ID, "_"), "internal check listed: %s", def.ID)
		assert.False(t, ids[def.ID], "duplicate check %s", def.ID)
		assert.Less(t, previous, def.ID, "catalog is sorted by ID")
		previous = def.ID
		ids[def.ID] = true
	}

	// one check per scenario family
	assert.True(t, ids["graphql.introspection_enabled"])
	assert.True(t, ids["discover.exposed_files"])
	assert.True(t, ids["misconfiguration.http_trace"])
	assert.True(t, ids["broken_authentication.authentication_bypass"])
}
