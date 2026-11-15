package expiredaccepted

import (
	expiredaccepted "github.com/cerberauth/jwtop/jwt/crack/checks/expired_accepted"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(expiredaccepted.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-expired?utm_source=vulnapi-report")

var Check = checkbase.Adapt(expiredaccepted.Check)
