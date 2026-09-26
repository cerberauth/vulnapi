// Package hmacconfusion adapts jwtop's hmac_confusion crack check as a
// vulnapi check.
package hmacconfusion

import (
	hmacconfusion "github.com/cerberauth/jwtop/jwt/crack/checks/hmac_confusion"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(hmacconfusion.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-algorithm-confusion?utm_source=vulnapi-report")

var Check = checkbase.Adapt(hmacconfusion.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.hmac_confusion", "jwt.algorithm_confusion")
}
