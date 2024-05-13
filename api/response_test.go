package api_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/api"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestMarshalHTTPResponseReports(t *testing.T) {
	sr := report.NewScanReport("id", "test", nil)
	sr.StartTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	sr.EndTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	hrr := api.HTTPResponseReports{
		Reports: []*report.ScanReport{sr},
	}

	b, err := json.Marshal(hrr)

	assert.NoError(t, err)
	assert.NotEmpty(t, b)
}
