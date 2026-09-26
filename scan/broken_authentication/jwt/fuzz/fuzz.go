// Package fuzz adapts jwtop's fuzz (claim-mutation) crack check as a
// vulnapi check.
package fuzz

import (
	fuzz "github.com/cerberauth/jwtop/jwt/crack/checks/fuzz"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(fuzz.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-claim-fuzzing?utm_source=vulnapi-report")

var Check = checkbase.Adapt(fuzz.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.fuzz", "jwt.claim_fuzzing")
}
