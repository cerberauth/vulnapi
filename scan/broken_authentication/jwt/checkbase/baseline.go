package checkbase

import (
	"github.com/cerberauth/jwtop/jwt/crack/checks/baseline"
)

// BaselineCheck adapts jwtop's baseline crack check — every other JWT check
// depends on it — as a genuine vulnapi check. It has no CheckDef (like
// scan/misconfiguration/http_cookies_fetch): baseline's own Result.Data is a
// harnessx.Snapshot other checks' baseline comparisons depend on, not a
// reportable finding.
var BaselineCheck = Adapt(baseline.Check)
