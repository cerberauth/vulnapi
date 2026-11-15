package issuernotvalidated

import (
	issuernotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/issuer_not_validated"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(issuernotvalidated.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-cross-service-relay-attack?utm_source=vulnapi-report")

var Check = checkbase.Adapt(issuernotvalidated.Check)
