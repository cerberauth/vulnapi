package robot

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	parobot "github.com/cerberauth/proxyaudit/proxy/checks/tls/robot"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("robot", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, parobot.Check.ID, parobot.CodeROBOT)
