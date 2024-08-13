package discover_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/cmd/discover"
	"github.com/stretchr/testify/assert"
)

func TestNewDiscoverCmd(t *testing.T) {
	scanCmd := discover.NewDiscoverCmd()

	assert.NotNil(t, scanCmd)

	// Assert that NewCURLScanCmd and NewOpenAPIScanCmd commands are added
	assert.NotNil(t, scanCmd.Commands())
}
