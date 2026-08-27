// Package finding defines the payload checks attach to a harnessx.Result
// when they detect a vulnerability. scan.Scan's harnessx.Reporter bridge
// reads it back out and turns it into a reportx.Finding.
package finding

import (
	"github.com/cerberauth/vulnapi/internal/operation"
)

// Finding is the payload a check returns (as harnessx.Result.Data) when it
// detects a vulnerability. A check that passes returns a bare
// harnessx.Result{} instead - the presence of a *Finding is itself the
// vulnerable/not-vulnerable signal.
type Finding struct {
	// Operation identifies the affected operation for ScopeGlobal checks
	// (which have no harnessx.Result.ResourceID to resolve one from). Leave
	// nil for ScopePerResource checks - the bridge resolves the operation
	// from the resource that was scanned.
	Operation *operation.Operation

	// Parameter is the crafted payload / discovered value (e.g. the cracked
	// secret, the alg=none variant used, the discovered path).
	Parameter string

	// Attempt is the decisive request/response that proves the finding, if
	// any (nil for offline checks, e.g. cryptographic secret cracking).
	Attempt *Attempt

	// Extra carries anything else worth keeping in the report.
	Extra map[string]string

	// Data carries check-specific structured data for dependent checks to
	// read back out via harnessx.ResultStore (e.g. the winning
	// *operation.Operation a downstream check needs to replay). Most checks
	// leave this nil - it exists for the rare case where a check both
	// reports its own finding and feeds a typed payload to a dependent
	// check.
	Data any
}
