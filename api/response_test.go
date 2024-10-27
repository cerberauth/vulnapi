package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/cerberauth/vulnapi/api"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/report"
	"github.com/stretchr/testify/assert"
)

func TestMarshalHTTPResponseReports(t *testing.T) {
	op := operation.MustNewOperation(http.MethodPost, "http://localhost:8080/", nil, nil)
	sr := report.NewScanReport("id", "test", op)
	sr.StartTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	sr.EndTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	hrr := api.HTTPResponseReports{
		Reports: []*report.ScanReport{sr},
	}

	b, err := json.Marshal(hrr)

	assert.NoError(t, err)
	assert.NotEmpty(t, b)
}
