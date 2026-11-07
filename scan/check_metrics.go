package scan

import (
	"context"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/vulnapi/internal/telemetry"
	"github.com/cerberauth/x/telemetryx/scanmetrics"
	"github.com/getargvio/argvio-go"
)

// checkErrors says which checks fail and why, declared in the Argvio catalog. scanmetrics
// counts the checks by outcome and times them.
var checkErrors = argvio.NewCounter("scan.check-errors", argvio.Dims("check", "reason"))

// checkMetricsReporter implements harnessx.Reporter. Only check IDs chosen in
// code and the class of an error (never its message) are sent.
type checkMetricsReporter struct {
	ctx context.Context
}

func newCheckMetricsReporter(ctx context.Context) *checkMetricsReporter {
	return &checkMetricsReporter{ctx: ctx}
}

func (r *checkMetricsReporter) OnScanStart(harnessx.Target, int)                                 {}
func (r *checkMetricsReporter) OnCheckStart(harnessx.Check, harnessx.Target, *harnessx.Resource) {}
func (r *checkMetricsReporter) OnScanComplete(harnessx.ScanSummary)                              {}

func (r *checkMetricsReporter) OnCheckComplete(result harnessx.Result) {
	if isInternalCheckID(string(result.CheckID)) {
		return
	}
	check := scanmetrics.Identifier(string(result.CheckID))
	if result.Err != nil {
		checkErrors.Add(r.ctx, 1, check, telemetry.ErrorClass(result.Err))
	}
}
