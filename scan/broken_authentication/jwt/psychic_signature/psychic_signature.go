// Package psychicsignature adapts jwtop's psychic_signature crack check as
// a vulnapi check.
package psychicsignature

import (
	psychicsignature "github.com/cerberauth/jwtop/jwt/crack/checks/psychic_signature"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(psychicsignature.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-psychic-signature?utm_source=vulnapi-report")

var Check = checkbase.Adapt(psychicsignature.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.psychic_signature")
}
