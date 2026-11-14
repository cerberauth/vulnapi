// Package kidsqlinjection adapts jwtop's kid_sql_injection crack check as
// a vulnapi check.
package kidsqlinjection

import (
	kidsqlinjection "github.com/cerberauth/jwtop/jwt/crack/checks/kid_sql_injection"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(kidsqlinjection.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection?utm_source=vulnapi-report")

// Check iterates the table-name candidates set on the probe context
// (checkbase.KidSQLTableCandidates) itself, stopping at the first one that
// proves vulnerable.
var Check = checkbase.Adapt(kidsqlinjection.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.kid_injection", "kid_sql_injection")
}
