package httpaccepted

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	httpsredirect "github.com/cerberauth/proxyaudit/proxy/checks/tls/https_redirect"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("http_accepted", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, httpsredirect.Check.ID, httpsredirect.CodeNotRedirected, httpsredirect.CodeNotHTTPS)
