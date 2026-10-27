package cmd_test

import (
	"testing"

	"github.com/cerberauth/cobracurl"
	"github.com/cerberauth/vulnapi/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHTTPClientFromCmdAppliesDefaultTimeout(t *testing.T) {
	client, err := cmd.NewHTTPClientFromCmd(&cobra.Command{})

	require.NoError(t, err)
	assert.Equal(t, cmd.DefaultHTTPTimeout, client.Timeout)
}

func TestNewHTTPClientFromCmdMaxTimeOverridesDefaultTimeout(t *testing.T) {
	c := &cobra.Command{}
	cobracurl.RegisterMaxTimeFlag(c.Flags())
	require.NoError(t, c.Flags().Set("max-time", "2"))

	client, err := cmd.NewHTTPClientFromCmd(c)

	require.NoError(t, err)
	assert.Equal(t, 2.0, client.Timeout.Seconds())
}
