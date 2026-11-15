package forwardsecrecymissing

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	cipherstrength "github.com/cerberauth/proxyaudit/proxy/checks/tls/cipher_strength"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("forward_secrecy_missing", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, cipherstrength.Check.ID, cipherstrength.CodeNoForwardSecrecy, cipherstrength.CodeWeakDH)
