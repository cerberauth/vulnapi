// Package kidpathtraversal adapts jwtop's kid_path_traversal crack check
// as a vulnapi check.
package kidpathtraversal

import (
	kidpathtraversal "github.com/cerberauth/jwtop/jwt/crack/checks/kid_path_traversal"
	"github.com/cerberauth/vulnapi/scan"
	"github.com/cerberauth/vulnapi/scan/broken_authentication/jwt/checkbase"
)

var Def = checkbase.WithLink(kidpathtraversal.Def, "https://www.cerberauth.com/docs/vulnapi/vulnerabilities/broken-authentication/jwt-kid-injection?utm_source=vulnapi-report")

var Check = checkbase.Adapt(kidpathtraversal.Check)

func init() {
	scan.RegisterLegacyCheckIDAlias(string(Check.ID), "jwt.kid_injection", "kid_path_traversal")
}
