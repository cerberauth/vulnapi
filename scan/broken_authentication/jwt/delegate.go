package jwt

import (
	"context"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/jwtop/jwt/crack"
	"github.com/cerberauth/jwtop/jwt/crack/checkbase"
	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	hmacconfusion "github.com/cerberauth/jwtop/jwt/crack/checks/hmac_confusion"
	jkuinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jku_injection"
	jwkinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jwk_injection"
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
	psychicsignature "github.com/cerberauth/jwtop/jwt/crack/checks/psychic_signature"
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
	x5cinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5c_injection"
	x5uinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5u_injection"
	"github.com/cerberauth/jwtop/jwt/exploit"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/jwtcheck"
)

// kidSQLTableCandidates lists table names tried, in order, for the
// kid_sql_injection check's payload until one yields a vulnerable result.
// The vulnerable table name is server-specific and can't be discovered by
// the check itself. A future PR will make this configurable via a config
// file; for now this covers common naming schemes.
var kidSQLTableCandidates = []string{
	exploit.DefaultKidSQLTable,
	"keys",
	"jwt_keys",
	"api_keys",
	"secrets",
	"users",
}

func probeResultOf(r harnessx.Result) (checkbase.ProbeResult, bool) {
	if pr, ok := harnessx.DataAs[checkbase.ProbeResult](r); ok {
		return pr, true
	}
	return checkbase.ResolveVariantResult(r.Attempts)
}

func newDelegatedCheck(jc harnessx.Check, def hxcheckdef.CheckDef) harnessx.Check {
	def.DependsOn = []string{string(jwtProbeCheckID)}
	return hxcheckdef.NewResourceCheck(def, func(_ context.Context, _ harnessx.Target, resource harnessx.Resource, store harnessx.ResultStore) (harnessx.Result, error) {
		loaderResult, ok := store.GetForResource(jwtProbeCheckID, resource.ID)
		if !ok || loaderResult.Skipped {
			return harnessx.Result{Skipped: true, SkipReason: "jwt probe did not run"}, nil
		}
		results, ok := harnessx.DataAs[map[harnessx.CheckID]harnessx.Result](loaderResult)
		if !ok {
			return harnessx.Result{}, nil
		}
		r, ok := results[jc.ID]
		if !ok {
			return harnessx.Result{}, nil
		}
		if r.Skipped {
			return harnessx.Result{Skipped: true, SkipReason: r.SkipReason}, nil
		}
		pr, ok := probeResultOf(r)
		if !ok || !pr.Vulnerable {
			return harnessx.Result{}, nil
		}
		return harnessx.Result{Data: &finding.Finding{Parameter: pr.Payload, Data: pr}}, nil
	},
		hxcheckdef.WithSkip(jwtcheck.SkipUnlessJWT()),
	)
}

// links overrides jwtop's own Def.Link with vulnapi-specific docs for
// checks that have a vulnapi advisory page. Checks with no entry here keep
// jwtop's own Link (already a valid cerberauth.com/docs/jwtop URL).
var links = map[harnessx.CheckID]string{
	blanksecret.Check.ID:      "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-blank-secret?utm_source=vulnapi-report",
	nullsignature.Check.ID:    "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-null-signature?utm_source=vulnapi-report",
	weaksecret.Check.ID:       "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-weak-secret?utm_source=vulnapi-report",
	kidsqlinjection.Check.ID:  "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection?utm_source=vulnapi-report",
	kidpathtraversal.Check.ID: "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection?utm_source=vulnapi-report",
	algnone.Check.ID:          "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-alg-none?utm_source=vulnapi-report",
	hmacconfusion.Check.ID:    "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-algorithm-confusion?utm_source=vulnapi-report",
	psychicsignature.Check.ID: "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-psychic-signature?utm_source=vulnapi-report",
	jwkinjection.Check.ID:     "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-jwk-injection?utm_source=vulnapi-report",
	jkuinjection.Check.ID:     "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-jku-injection?utm_source=vulnapi-report",
	x5cinjection.Check.ID:     "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-x5c-injection?utm_source=vulnapi-report",
	x5uinjection.Check.ID:     "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-x5u-injection?utm_source=vulnapi-report",
}

func WithJWTChecks(s *scan.Scan) *scan.Scan {
	s.AddCheck(newJWTProbeCheck(), nil)

	// Checks come from jwtop's own registry rather than a hand-maintained
	// list, so vulnapi always exposes exactly the checks jwtop's probe
	// actually runs. Each takes its jwtop Def as-is (name, description,
	// tags, CVSS/CWE/OWASP) except link (see links above) and DependsOn,
	// cleared since jwtop's depends_on refers to jwtop-internal check IDs
	// the delegate check doesn't register as harnessx checks (gating
	// instead happens via jwtProbeCheckID).
	checks, defs := crack.BuildChecks()
	for _, jc := range checks {
		if jc.ID == checkbase.CheckIDBaseline {
			continue // not a reportable vulnerability check
		}
		def := defs[jc.ID]
		if link, ok := links[jc.ID]; ok {
			def.Link = link
		}
		def.DependsOn = nil
		s.AddCheck(newDelegatedCheck(jc, def), &def)
	}
	return s
}

func init() {
	scan.RegisterLegacyCheckIDAlias(string(blanksecret.Check.ID), "jwt.blank_secret", "blank_secret")
	scan.RegisterLegacyCheckIDAlias(string(noverification.Check.ID), "jwt.not_verified")
	scan.RegisterLegacyCheckIDAlias(string(nullsignature.Check.ID), "jwt.null_signature")
	scan.RegisterLegacyCheckIDAlias(string(weaksecret.Check.ID), "jwt.weak_secret", "weak_secret")
	scan.RegisterLegacyCheckIDAlias(string(kidsqlinjection.Check.ID), "jwt.kid_injection", "kid_sql_injection")
	scan.RegisterLegacyCheckIDAlias(string(kidpathtraversal.Check.ID), "jwt.kid_injection", "kid_path_traversal")
	scan.RegisterLegacyCheckIDAlias(string(algnone.Check.ID), "jwt.alg_none")
	scan.RegisterLegacyCheckIDAlias(string(hmacconfusion.Check.ID), "jwt.hmac_confusion", "jwt.algorithm_confusion")
	scan.RegisterLegacyCheckIDAlias(string(psychicsignature.Check.ID), "jwt.psychic_signature")
	scan.RegisterLegacyCheckIDAlias(string(jwkinjection.Check.ID), "jwt.jwk_injection")
	scan.RegisterLegacyCheckIDAlias(string(jkuinjection.Check.ID), "jwt.jku_injection")
	scan.RegisterLegacyCheckIDAlias(string(x5cinjection.Check.ID), "jwt.x5c_injection")
	scan.RegisterLegacyCheckIDAlias(string(x5uinjection.Check.ID), "jwt.x5u_injection")
}
