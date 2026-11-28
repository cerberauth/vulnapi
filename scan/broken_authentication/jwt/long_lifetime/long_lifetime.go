package longlifetime

import (
	longlifetime "github.com/cerberauth/jwtop/jwt/crack/checks/long_lifetime"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(longlifetime.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-expired?utm_source=vulnapi-report")

var Check = checkbase.Adapt(longlifetime.Check)
