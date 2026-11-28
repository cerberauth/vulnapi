// Package timestamptampering adapts jwtop's timestamp_tampering crack check
// as a vulnapi check.
package timestamptampering

import (
	timestamptampering "github.com/cerberauth/jwtop/jwt/crack/checks/timestamp_tampering"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(timestamptampering.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-timestamp-tampering?utm_source=vulnapi-report")

// Check re-signs the token with an expired exp claim. It needs the HMAC
// secret, either cracked by the weak_secret check or supplied with
// --jwt-secret.
var Check = checkbase.Adapt(timestamptampering.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.timestamp_tampering", "timestamptampering")
}
