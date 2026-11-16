// Package nullsignature runs jwtop's null_signature crack check as a
// vulnapi check.
package nullsignature

import (
	nullsignature "github.com/cerberauth/jwtop/jwt/crack/checks/null_signature"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(nullsignature.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-null-signature?utm_source=vulnapi-report")

var Check = checkbase.Check(nullsignature.Check.ID)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "nullsig")
}
