package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
)

// The reporter must not panic on any kind of result, with the Argvio client
// disabled as it is in tests, and must ignore internal checks.
func TestCheckMetricsReporterOnCheckComplete(t *testing.T) {
	r := newCheckMetricsReporter(context.Background())
	assert.NotPanics(t, func() {
		r.OnScanStart(harnessx.Target{}, 1)
		r.OnCheckComplete(harnessx.Result{CheckID: "jwt.none_algorithm", Duration: time.Second})
		r.OnCheckComplete(harnessx.Result{CheckID: "jwt.none_algorithm", Err: errors.New("boom")})
		r.OnCheckComplete(harnessx.Result{CheckID: "jwt.none_algorithm", Skipped: true})
		r.OnCheckComplete(harnessx.Result{CheckID: "_operations_loader", Err: errors.New("boom")})
		r.OnScanComplete(harnessx.ScanSummary{})
	})
}
