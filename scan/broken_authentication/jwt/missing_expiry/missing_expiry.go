package missingexpiry

import (
	missingexpiry "github.com/cerberauth/jwtop/jwt/crack/checks/missing_expiry"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(missingexpiry.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-expired?utm_source=vulnapi-report")

var Check = checkbase.Check(missingexpiry.Check.ID)
