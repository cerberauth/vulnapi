package claimremoval

import (
	claimremoval "github.com/cerberauth/jwtop/jwt/crack/checks/claim_removal"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(claimremoval.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-claims-not-validated?utm_source=vulnapi-report")

var Check = checkbase.Adapt(claimremoval.Check)
