package report_test

import (
	"testing"

	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestNewEmptyOptionsReport(t *testing.T) {
	optionsReport := report.NewEmptyOptionsReport()

	assert.NotNil(t, optionsReport)
	assert.Nil(t, optionsReport.ScansIncluded)
}
