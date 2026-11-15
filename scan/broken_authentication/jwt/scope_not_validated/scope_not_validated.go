package scopenotvalidated

import (
	scopenotvalidated "github.com/cerberauth/jwtop/jwt/crack/checks/scope_not_validated"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(scopenotvalidated.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-claims-not-validated?utm_source=vulnapi-report")

var Check = checkbase.Adapt(scopenotvalidated.Check)
