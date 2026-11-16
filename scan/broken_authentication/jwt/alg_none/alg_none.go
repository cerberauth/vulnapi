// Package algnone runs jwtop's alg_none crack check as a vulnapi check.
package algnone

import (
	algnone "github.com/cerberauth/jwtop/jwt/crack/checks/alg_none"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(algnone.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-alg-none?utm_source=vulnapi-report")

var Check = checkbase.Check(algnone.Check.ID)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "algnone")
}
