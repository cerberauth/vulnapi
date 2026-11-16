package drown

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	padrown "github.com/cerberauth/proxyaudit/proxy/checks/tls/drown"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("drown", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, padrown.Check.ID, padrown.CodeDROWN)
