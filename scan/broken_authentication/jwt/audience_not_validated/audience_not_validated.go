package audiencenotvalidated

import (
	audiencenotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/audience_not_validated"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(audiencenotvalidated.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-cross-service-relay-attack?utm_source=vulnapi-report")

var Check = checkbase.Adapt(audiencenotvalidated.Check)
