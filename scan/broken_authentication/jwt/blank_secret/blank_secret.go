// Package blanksecret adapts jwtop's blank_secret crack check as a vulnapi
// check.
package blanksecret

import (
	blanksecret "github.com/cerberauth/jwtop/jwt/crack/checks/blank_secret"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(blanksecret.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-blank-secret?utm_source=vulnapi-report")

var Check = checkbase.Adapt(blanksecret.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.blank_secret", "blank_secret")
}
