package discoverableopenapi

import (
	"context"
	_ "embed"
	"errors"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/scan/discover"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("discoverable_openapi", checkYAML)

var openapiSeclistUrl = "https://raw.githubusercontent.com/cerberauth/vulnapi/main/seclist/lists/swagger.txt"

var Check = hxcheckdef.NewCheck(Def, func(ctx context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	resources := store.Resources()
	if len(resources) == 0 {
		return harnessx.Result{Skipped: true, SkipReason: "no resources"}, nil
	}
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resources[0])
	if !ok {
		return harnessx.Result{Err: errors.New("discoverable_openapi: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()

	f, err := discover.DownloadAndScanURLs(ctx, "OpenAPI", openapiSeclistUrl, op, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}
	if f == nil {
		return harnessx.Result{}, nil
	}
	f.Operation = op
	return harnessx.Result{Data: f}, nil
})
