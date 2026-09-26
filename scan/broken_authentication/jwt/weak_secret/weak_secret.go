// Package weaksecret adapts jwtop's weak_secret crack check as a vulnapi
// check.
package weaksecret

import (
	weaksecret "github.com/cerberauth/jwtop/jwt/crack/checks/weak_secret"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(weaksecret.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-weak-secret?utm_source=vulnapi-report")

var Check = checkbase.Adapt(weaksecret.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.weak_secret", "weak_secret")
}
