package protocoldeprecated

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	protocolversion "github.com/cerberauth/proxyaudit/proxy/checks/tls/protocol_version"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("protocol_deprecated", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, protocolversion.Check.ID, protocolversion.CodeLegacyEnabled)
