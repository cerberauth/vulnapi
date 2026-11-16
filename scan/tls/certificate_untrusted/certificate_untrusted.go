package certificateuntrusted

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/certificate"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("certificate_untrusted", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, certificate.Check.ID, certificate.CodeSelfSigned, certificate.CodeUntrustedChain)
