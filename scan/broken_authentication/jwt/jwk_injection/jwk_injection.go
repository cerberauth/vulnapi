// Package jwkinjection adapts jwtop's jwk_injection crack check as a
// vulnapi check.
package jwkinjection

import (
	jwkinjection "github.com/cerberauth/jwtop/jwt/crack/checks/jwk_injection"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(jwkinjection.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-jwk-injection?utm_source=vulnapi-report")

var Check = checkbase.Adapt(jwkinjection.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.jwk_injection")
}
