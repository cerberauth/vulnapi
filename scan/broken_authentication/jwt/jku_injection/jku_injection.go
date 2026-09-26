// Package jkuinjection adapts jwtop's jku_injection crack check as a
// vulnapi check.
package jkuinjection

import (
	jkuinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jku_injection"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(jkuinjection.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-jku-injection?utm_source=vulnapi-report")

var Check = checkbase.Adapt(jkuinjection.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.jku_injection")
}
