package scan

import (
	"context"
	"sync"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/reportx"
	"github.com/cerberauth/reportx/enrich"
	"github.com/cerberauth/reportx/score"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
)

const operationsLoaderCheckID harnessx.CheckID = "_operations"

const defaultToolName = "vulnapi"

func newOperationsLoaderCheck(ops operation.Operations) harnessx.Check {
	return harnessx.Check{
		ID:    operationsLoaderCheckID,
		Name:  "Operations Loader",
		Scope: harnessx.ScopeGlobal,
		Run: func(_ context.Context, _ harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
			resources := make([]harnessx.Resource, len(ops))
			for i, op := range ops {
				resources[i] = harnessx.Resource{
					ID:     op.ID,
					URL:    op.URL.String(),
					Method: op.Method,
					Data:   op,
				}
			}
			return harnessx.Result{Resources: resources}, nil
		},
	}
}

// harnessxReporter bridges harnessx's live Reporter hooks to reportx: it
// accumulates reportx.Findings as checks complete and builds the final
// *reportx.Report once the scan finishes.
type harnessxReporter struct {
	title       string
	toolVersion string
	checkDefs   map[harnessx.CheckID]checkdef.CheckDef

	mu        sync.Mutex
	target    string
	resources map[string]*operation.Operation
	findings  []reportx.Finding
	report    *reportx.Report

	callback func(*OperationScan)
}

func (a *harnessxReporter) OnScanStart(target harnessx.Target, _ int) {
	a.mu.Lock()
	a.target = target.URL
	a.resources = make(map[string]*operation.Operation)
	a.mu.Unlock()
}

func (a *harnessxReporter) OnCheckStart(_ harnessx.Check, _ harnessx.Target, _ *harnessx.Resource) {}

func (a *harnessxReporter) OnCheckComplete(result harnessx.Result) {
	if result.CheckID == operationsLoaderCheckID {
		a.mu.Lock()
		for _, res := range result.Resources {
			if op, ok := harnessx.ResourceDataAs[*operation.Operation](res); ok {
				a.resources[res.ID] = op
			}
		}
		a.mu.Unlock()
	} else if f, ok := harnessx.DataAs[*finding.Finding](result); ok && f != nil {
		def := a.checkDefs[result.CheckID]

		op := f.Operation
		a.mu.Lock()
		if op == nil {
			op = a.resources[result.ResourceID]
		}
		target := a.target
		a.findings = append(a.findings, toFinding(def, f, op, target))
		a.mu.Unlock()
	}

	if a.callback != nil {
		a.callback(nil)
	}
}

func (a *harnessxReporter) OnScanComplete(_ harnessx.ScanSummary) {
	a.mu.Lock()
	findings := a.findings
	target := a.target
	a.mu.Unlock()

	if target == "" {
		target = "(offline)"
	}

	report, _ := reportx.NewBuilder().
		Title(a.title).
		Tool(defaultToolName, a.toolVersion).
		Target(target).
		Findings(findings).
		Enrich(enrich.EnrichAll).
		Build(context.Background())

	a.mu.Lock()
	a.report = report
	a.mu.Unlock()
}

// Report returns the reportx.Report built from the scan. Safe to call once
// the harnessx engine.Run that registered this reporter has returned, since
// OnScanComplete runs synchronously beforehand.
func (a *harnessxReporter) Report() *reportx.Report {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.report
}

func toFinding(def checkdef.CheckDef, f *finding.Finding, op *operation.Operation, target string) reportx.Finding {
	now := time.Now()

	rf := reportx.Finding{
		ID:           def.ID,
		Title:        def.Name,
		Severity:     score.Label(def.CVSSScore),
		CVSS40Score:  def.CVSSScore,
		CVSS40Vector: def.CVSSVector,
		CWEID:        def.CWEID,
		OwaspTop10:   def.OWASP,
		CAPECID:      def.CAPECID,
		URL:          def.Link,
		Parameter:    f.Parameter,
		Description:  def.Description,
		Status:       reportx.StatusActive,
		FirstSeen:    now,
		LastSeen:     now,
		Tags:         def.Tags,
	}

	extra := map[string]string{}
	if op != nil {
		rf.URL = op.URL.String()
		extra["operation_id"] = op.GetID()
		extra["operation_method"] = op.Method
		if ss := op.GetSecurityScheme(); ss != nil {
			extra["security_scheme_type"] = string(ss.GetType())
			extra["security_scheme_scheme"] = string(ss.GetScheme())
			extra["security_scheme_name"] = ss.GetName()
		}
	} else if target != "" {
		rf.URL = target
	}
	if ev := finding.NewHTTPEvidence(f.Attempt); ev != nil {
		rf.Evidence = ev
		extra["attempt_id"] = f.Attempt.ID
	}
	for k, v := range f.Extra {
		extra[k] = v
	}
	if len(extra) > 0 {
		rf.Extra = extra
	}

	return rf
}
