// Package x5cinjection adapts jwtop's x5c_injection crack check as a
// vulnapi check.
package x5cinjection

import (
	x5cinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5c_injection"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(x5cinjection.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-x5c-injection?utm_source=vulnapi-report")

var Check = checkbase.Adapt(x5cinjection.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.x5c_injection")
}
