package checkbase

import (
	"context"
	"sync"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	"github.com/cerberauth/vulnapi/internal/finding"
)

func probeResultOf(r harnessx.Result) (checkbase.ProbeResult, bool) {
	if pr, ok := harnessx.DataAs[checkbase.ProbeResult](r); ok {
		return pr, true
	}
	return checkbase.ResolveVariantResult(r.Attempts)
}

// resourceScopedStore adapts vulnapi's per-resource ResultStore onto the
// single-target store.Get(id) jwtop's checks are written against: jwtop
// scans exactly one target per engine run, so its own checks read a
// dependency's result via store.Get(id) rather than
// store.GetForResource(id, resourceID). vulnapi's shared engine runs the
// same jwtop CheckID once per JWT-bearing resource, so Get here is
// redirected to this resource's own GetForResource result — without this,
// every jwtop check would see every *other* resource's result (or none) for
// store.Get(id) instead of its own.
type resourceScopedStore struct {
	harnessx.ResultStore
	resourceID string
}

func (s resourceScopedStore) Get(id harnessx.CheckID) (harnessx.Result, bool) {
	return s.GetForResource(id, s.resourceID)
}

// toFindingResult turns a jwtop check's raw Result — whose Data is a
// checkbase.ProbeResult for an ordinary check, or resolved from Attempts for
// a Variants check (see runOf) — into vulnapi's finding.Finding convention:
// only a vulnerable probe result is ever reported.
func toFindingResult(r harnessx.Result) harnessx.Result {
	if r.Err != nil || r.Skipped {
		return r
	}
	pr, ok := probeResultOf(r)
	if !ok || !pr.Vulnerable {
		return harnessx.Result{}
	}
	return harnessx.Result{Data: &finding.Finding{Parameter: pr.Payload, Data: pr}}
}

// runOf returns a plain harnessx.CheckFunc for jc: jc.Run directly for an
// ordinary check, or — for a Variants check (only alg_none, today) — a func
// that runs every variant (respecting jc.VariantMode) via jc.RunVariant and
// reduces them with jwtop's own checkbase.ResolveVariantResult, the same
// reduction jwtop's ProbeAll relies on. harnessx's own variant fan-out/
// aggregation (runVariants/aggregateAttempts) is engine-internal, so this
// mirrors just enough of it to let Adapt's RunResource stay uniform
// regardless of whether the underlying jwtop check is variant-based.
func runOf(jc harnessx.Check) harnessx.CheckFunc {
	if len(jc.Variants) == 0 {
		return jc.Run
	}

	variants := jc.Variants
	runVariant := jc.RunVariant
	parallel := jc.VariantMode == harnessx.VariantsParallel

	return func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
		attempts := make([]harnessx.Attempt, len(variants))
		runAttempt := func(i int, variant string) {
			start := time.Now()
			result, err := runVariant(ctx, target, variant, store)
			if err == nil {
				err = result.Err
			}
			attempts[i] = harnessx.Attempt{
				Variant:      variant,
				Observations: result.Observations,
				Resources:    result.Resources,
				Data:         result.Data,
				Err:          err,
				Duration:     time.Since(start),
			}
		}

		if parallel {
			var wg sync.WaitGroup
			for i, variant := range variants {
				wg.Add(1)
				go func(i int, variant string) {
					defer wg.Done()
					runAttempt(i, variant)
				}(i, variant)
			}
			wg.Wait()
		} else {
			for i, variant := range variants {
				runAttempt(i, variant)
			}
		}

		result := harnessx.Result{Attempts: attempts}
		for _, a := range attempts {
			result.Observations = append(result.Observations, a.Observations...)
			result.Resources = append(result.Resources, a.Resources...)
			if result.Err == nil && a.Err != nil {
				result.Err = a.Err
			}
		}
		return result, nil
	}
}

// Option configures Adapt's optional behavior.
type Option func(*adaptConfig)

type adaptConfig struct {
	wrapRun func(harnessx.CheckFunc) harnessx.CheckFunc
}

// WithRunWrapper wraps the composed run function (jc.Run, or the
// variant-reducing func runOf builds for a Variants check) before Adapt
// embeds it into the returned Check's RunResource. Used only by
// kid_sql_injection today, to retry with different table-name candidates.
func WithRunWrapper(wrap func(harnessx.CheckFunc) harnessx.CheckFunc) Option {
	return func(cfg *adaptConfig) {
		cfg.wrapRun = wrap
	}
}

// WithLink returns a copy of def with Link overridden — for the checks
// that have a vulnapi-specific advisory page. Checks that don't call this
// keep jwtop's own Link (already a valid cerberauth.com/docs/jwtop URL).
func WithLink(def checkdef.CheckDef, link string) checkdef.CheckDef {
	def.Link = link
	return def
}

// Adapt turns a ScopeGlobal jwtop check — written to scan exactly one
// target per engine run, reading its *checkbase.ProbeCtx from target.Data —
// into a genuine ScopePerResource vulnapi check that runs once per
// JWT-bearing resource. It keeps jc's ID, DependsOn, Skip, and
// Run/RunVariant logic completely as jwtop wrote them: jc.ID stays the
// CheckID users select via --scans/--exclude-scans, jc.DependsOn keeps
// jwtop's own dependency graph (baseline, secret, ...) intact in vulnapi's
// shared engine's single topological sort (plus ProbeCtxCheckID, which
// every adapted check also depends on directly), and jc.Run/jc.RunVariant/
// jc.Skip run unmodified against the synthetic single-target Target
// innerTargetFor builds for each resource — Adapt only adapts the Scope
// and translates the final ProbeResult into a finding.Finding.
func Adapt(jc harnessx.Check, opts ...Option) harnessx.Check {
	var cfg adaptConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	run := runOf(jc)
	if cfg.wrapRun != nil {
		run = cfg.wrapRun(run)
	}

	dependsOn := append([]harnessx.CheckID{ProbeCtxCheckID}, jc.DependsOn...)

	return harnessx.Check{
		ID:          jc.ID,
		Name:        jc.Name,
		Description: jc.Description,
		Link:        jc.Link,
		Tags:        jc.Tags,
		DependsOn:   dependsOn,
		Timeout:     jc.Timeout,
		Concurrency: jc.Concurrency,
		Scope:       harnessx.ScopePerResource,
		Skip: harnessx.SkipResourceWhen(func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) string {
			if reason := SkipUnlessJWT().EvalResource(ctx, harnessx.Target{}, resource, store); reason != "" {
				return reason
			}
			innerTarget, err := innerTargetFor(resource, store)
			if err != nil {
				return "jwt probe context unavailable: " + err.Error()
			}
			return jc.Skip.Eval(ctx, innerTarget, resourceScopedStore{ResultStore: store, resourceID: resource.ID})
		}),
		RunResource: func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
			innerTarget, err := innerTargetFor(resource, store)
			if err != nil {
				return harnessx.Result{}, err
			}
			scoped := resourceScopedStore{ResultStore: store, resourceID: resource.ID}
			result, runErr := run(ctx, innerTarget, scoped)
			if runErr != nil || jc.ID == checkbase.CheckIDBaseline {
				// baseline's own Result.Data is a harnessx.Snapshot other
				// checks' baseline comparisons depend on (via
				// resourceScopedStore.Get) — it must reach the store
				// untouched, not run through toFindingResult, which only
				// understands the checkbase.ProbeResult shape every other
				// jwtop check returns and would otherwise discard it.
				return result, runErr
			}
			return toFindingResult(result), nil
		},
	}
}
