// Package x5uinjection adapts jwtop's x5u_injection crack check as a
// vulnapi check.
package x5uinjection

import (
	x5uinjection "github.com/cerberauth/jwtop/jwt/crack/checks/x5u_injection"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(x5uinjection.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-x5u-injection?utm_source=vulnapi-report")

var Check = checkbase.Adapt(x5uinjection.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.x5u_injection")
}
