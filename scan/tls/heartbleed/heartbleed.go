package heartbleed

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	paheartbleed "github.com/cerberauth/proxyaudit/proxy/checks/tls/heartbleed"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("heartbleed", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, paheartbleed.Check.ID, paheartbleed.CodeHeartbleed)
