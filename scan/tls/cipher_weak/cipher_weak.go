package cipherweak

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
	cipherstrength "github.com/cerberauth/proxyaudit/proxy/checks/tls/cipher_strength"
	tlsfetch "github.com/cerberauth/vulnapi/scan/tls/fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cipher_weak", checkYAML)

var Check = tlsfetch.NewCodeCheck(Def, cipherstrength.Check.ID, cipherstrength.CodeRC4, cipherstrength.CodeTripleDES, cipherstrength.CodeNULL, cipherstrength.CodeWeakSuite)
