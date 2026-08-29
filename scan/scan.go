package scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/reportx"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/x/telemetryx"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type ScanOptions struct {
	IncludeScans []string
	ExcludeScans []string

	// MinSeverity, when set, restricts the scan to checks whose static
	// CVSS score (from their CheckDef) is >= *MinSeverity — checks that
	// can never reach the severity threshold don't run at all. A
	// dependency of a kept check still runs regardless of its own score.
	MinSeverity *float64

	// Title names the report (e.g. "cURL Scan", "OpenAPI Scan"). Defaults to
	// "Scan" when empty.
	Title string
	// ToolVersion is recorded in the report metadata.
	ToolVersion string
}

type Scan struct {
	*ScanOptions

	Operations      operation.Operations
	OperationsScans []OperationScan

	harnessxChecks []harnessx.Check
	checkDefs      map[harnessx.CheckID]checkdef.CheckDef

	telemetryOperationScanHandler metric.Int64Counter
}

const (
	otelName = "github.com/cerberauth/vulnapi/scan"

	otelScanIncludeScansAttribute = attribute.Key("include_scans")
	otelScanExcludeScansAttribute = attribute.Key("exclude_scans")
	otelScanHandlerIdAttribute    = attribute.Key("id")
)

func NewScan(operations operation.Operations, opts *ScanOptions) (*Scan, error) {
	if len(operations) == 0 {
		return nil, fmt.Errorf("a scan must have at least one operation")
	}

	if opts == nil {
		opts = &ScanOptions{}
	}
	if opts.Title == "" {
		opts.Title = "Scan"
	}

	telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
	telemetryScanCounter, _ := telemetryMeter.Int64Counter("scan.counter")
	telemetryOperationScanHandlerCounter, _ := telemetryMeter.Int64Counter("scan.operation_scan_handler.counter")
	telemetryScanCounter.Add(context.Background(), 1, metric.WithAttributes(
		otelScanIncludeScansAttribute.StringSlice(opts.IncludeScans),
		otelScanExcludeScansAttribute.StringSlice(opts.ExcludeScans),
	))

	return &Scan{
		ScanOptions: opts,

		Operations:      operations,
		OperationsScans: []OperationScan{},
		harnessxChecks:  []harnessx.Check{},
		checkDefs:       map[harnessx.CheckID]checkdef.CheckDef{},

		telemetryOperationScanHandler: telemetryOperationScanHandlerCounter,
	}, nil
}

func (s *Scan) GetOperationsScans() []OperationScan {
	return s.OperationsScans
}

// AddCheck registers check with the scan. def supplies the CVSS/CWE/OWASP/
// CAPEC classification used to build a reportx.Finding when the check
// reports a vulnerability; pass nil for checks that never do (e.g. pure
// data-provider checks other checks depend on).
//
// check is always registered with the harnessx engine, even when it doesn't
// match --scans/--exclude-scans: Execute lets the engine decide the final
// run set via RunOption, which keeps a check's dependencies intact even if
// they wouldn't otherwise match the filter (see runOptions). OperationsScans
// — used for progress reporting — still only counts checks that match, plus
// internal (data-provider) checks, which are never user-selectable.
func (s *Scan) AddCheck(check harnessx.Check, def *checkdef.CheckDef) *Scan {
	if isInternalCheckID(string(check.ID)) || s.shouldAddScan(string(check.ID)) {
		if check.RunResource != nil {
			for _, op := range s.Operations {
				s.OperationsScans = append(s.OperationsScans, OperationScan{
					Operation: op,
					CheckID:   string(check.ID),
					CheckName: check.Name,
				})
			}
			s.telemetryOperationScanHandler.Add(context.Background(), int64(len(s.Operations)), metric.WithAttributes(
				otelScanHandlerIdAttribute.String(string(check.ID)),
			))
		} else {
			s.OperationsScans = append(s.OperationsScans, OperationScan{
				Operation: s.Operations[0],
				CheckID:   string(check.ID),
				CheckName: check.Name,
			})
			s.telemetryOperationScanHandler.Add(context.Background(), 1, metric.WithAttributes(
				otelScanHandlerIdAttribute.String(string(check.ID)),
			))
		}
	}
	if def != nil {
		s.checkDefs[check.ID] = *def
		// Mirror the classification onto the harnessx.Check itself so
		// harnessx.WithMinCVSSScore (see runOptions) can filter on it
		// directly, even for checks built as a raw harnessx.Check{}
		// literal instead of via checkdef.NewCheck.
		check.CVSSVector = def.CVSSVector
		check.CVSSScore = def.CVSSScore
		check.CWEID = def.CWEID
		check.CAPECID = def.CAPECID
		check.OWASP = def.OWASP
	}
	check.DependsOn = append([]harnessx.CheckID{operationsLoaderCheckID}, check.DependsOn...)
	s.harnessxChecks = append(s.harnessxChecks, check)
	return s
}

func (s *Scan) Execute(ctx context.Context, scanCallback func(operationScan *OperationScan)) (*reportx.Report, []error, error) {
	if scanCallback == nil {
		scanCallback = func(operationScan *OperationScan) {}
	}

	adapter := &harnessxReporter{
		title:       s.Title,
		toolVersion: s.ToolVersion,
		checkDefs:   s.checkDefs,
		callback:    scanCallback,
	}

	loaderCheck := newOperationsLoaderCheck(s.Operations)
	checks := append([]harnessx.Check{loaderCheck}, s.harnessxChecks...)

	engine := harnessx.New(
		harnessx.WithReporters(adapter),
	)
	if err := engine.Register(checks...); err != nil {
		return adapter.Report(), nil, err
	}

	target := harnessx.Target{URL: s.Operations[0].URL.String()}
	summary, err := engine.Run(ctx, target, s.runOptions()...)
	if err != nil {
		return adapter.Report(), nil, err
	}

	var errs []error
	for _, result := range summary.Results {
		if result.Err != nil {
			errs = append(errs, result.Err)
		}
	}

	return adapter.Report(), errs, nil
}

// legacyCheckIDAliases maps a check's current ID to IDs it was previously
// known under, so renamed/split checks keep matching users' existing
// --include-scans/--exclude-scans values. Populated at init time by the
// check packages that renamed their IDs (see RegisterLegacyCheckIDAlias).
var legacyCheckIDAliases = map[string][]string{}

// RegisterLegacyCheckIDAlias records that newID was previously known as one
// or more oldIDs, so shouldAddScan keeps matching the old IDs after a check
// is renamed or split. Intended to be called from a check package's init().
func RegisterLegacyCheckIDAlias(newID string, oldIDs ...string) {
	legacyCheckIDAliases[newID] = append(legacyCheckIDAliases[newID], oldIDs...)
}

func isInternalCheckID(id string) bool {
	return strings.HasPrefix(id, "_")
}

func (s *Scan) shouldAddScan(scanID string) bool {
	if len(s.ExcludeScans) > 0 && s.matchesExcludeScans(scanID) {
		return false
	}
	if len(s.IncludeScans) > 0 {
		return s.matchesIncludeScans(scanID)
	}
	return true
}

func (s *Scan) matchesExcludeScans(scanID string) bool {
	ids := append([]string{scanID}, legacyCheckIDAliases[scanID]...)
	for _, id := range ids {
		if contains(s.ExcludeScans, id) {
			return true
		}
	}
	return false
}

func (s *Scan) matchesIncludeScans(scanID string) bool {
	ids := append([]string{scanID}, legacyCheckIDAliases[scanID]...)
	for _, id := range ids {
		if contains(s.IncludeScans, id) {
			return true
		}
	}
	return false
}

// runOptions translates --scans/--exclude-scans/MinSeverity into harnessx
// RunOptions for Execute. --scans/--exclude-scans become a WithFilter
// wrapping shouldAddScan, and MinSeverity a WithFilter on CVSSScore (checks
// carry their static CVSSScore directly — mirrored from def in AddCheck —
// so no lookup into checkDefs is needed here). Both predicates always keep
// internal (data-provider) checks: harnessx.RunOption already preserves the
// transitive DependsOn closure of whatever passes the filters, so a
// dependency stays even if it wouldn't pass on its own — but a run whose
// filters match nothing would otherwise drop even the loader and error with
// ErrNoChecks, which internal checks are never meant to be subject to.
func (s *Scan) runOptions() []harnessx.RunOption {
	var opts []harnessx.RunOption
	if len(s.IncludeScans) > 0 || len(s.ExcludeScans) > 0 {
		opts = append(opts, harnessx.WithFilter(func(c harnessx.Check) bool {
			return isInternalCheckID(string(c.ID)) || s.shouldAddScan(string(c.ID))
		}))
	}
	if s.MinSeverity != nil {
		min := *s.MinSeverity
		opts = append(opts, harnessx.WithFilter(func(c harnessx.Check) bool {
			return isInternalCheckID(string(c.ID)) || c.CVSSScore >= min
		}))
	}
	return opts
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}

		match, _ := regexp.MatchString(s, item)
		if match {
			return true
		}
	}
	return false
}
