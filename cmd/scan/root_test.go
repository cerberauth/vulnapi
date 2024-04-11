package scan_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/cmd/scan"
	"github.com/stretchr/testify/assert"
)

func TestNewScanCmd(t *testing.T) {
	scanCmd := scan.NewScanCmd()

	assert.NotNil(t, scanCmd)

	// Assert that NewCURLScanCmd and NewOpenAPIScanCmd commands are added
	assert.NotNil(t, scanCmd.Commands())
}
