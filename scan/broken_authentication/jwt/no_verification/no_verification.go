// Package noverification adapts jwtop's no_verification crack check as a
// vulnapi check.
package noverification

import (
	noverification "github.com/cerberauth/jwtop/jwt/crack/checks/no_verification"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = noverification.Def

var Check = checkbase.Adapt(noverification.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.not_verified")
}
