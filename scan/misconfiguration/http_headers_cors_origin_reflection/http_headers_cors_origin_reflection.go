package httpheaderscorsoriginreflection

import (
	"context"
	_ "embed"
	"errors"
	"strings"

	"github.com/cerberauth/harnessx"
	hxcheckdef "github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/vulnapi/internal/finding"
	"github.com/cerberauth/vulnapi/internal/operation"
	httpheadersfetch "github.com/cerberauth/vulnapi/scan/misconfiguration/http_headers_fetch"
)

//go:embed check.yaml
var checkYAML []byte

var Def = hxcheckdef.MustParseCheckDefYAML("http_headers_cors_origin_reflection", checkYAML)

const (
	OriginHTTPHeader               = "Origin"
	CORSAllowCredentialsHTTPHeader = "Access-Control-Allow-Credentials"
	untrustedOrigin                = "https://vulnapi-cors-origin-reflection.example"
)

var Check = hxcheckdef.NewResourceCheck(Def, func(ctx context.Context, _ harnessx.Target, resource harnessx.Resource, _ harnessx.ResultStore) (harnessx.Result, error) {
	op, ok := harnessx.ResourceDataAs[*operation.Operation](resource)
	if !ok {
		return harnessx.Result{Err: errors.New("http_headers_cors_origin_reflection: resource missing *operation.Operation")}, nil
	}
	securityScheme := op.GetSecurityScheme()

	newOperation, err := op.Clone()
	if err != nil {
		return harnessx.Result{}, err
	}
	newOperation.Header = op.Header.Clone()
	if newOperation.Header == nil {
		newOperation.Header = map[string][]string{}
	}
	newOperation.Header.Set(OriginHTTPHeader, untrustedOrigin)

	attempt, err := finding.Fetch(ctx, newOperation, securityScheme)
	if err != nil {
		return harnessx.Result{}, err
	}

	header := attempt.Response.GetHeader()
	allowOrigin := header.Get(httpheadersfetch.CORSOriginHTTPHeader)
	if allowOrigin == "" {
		return harnessx.Result{Skipped: true, SkipReason: "CORS is not configured"}, nil
	}
	if allowOrigin != untrustedOrigin || !strings.EqualFold(strings.TrimSpace(header.Get(CORSAllowCredentialsHTTPHeader)), "true") {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Data: &finding.Finding{
		Parameter: httpheadersfetch.CORSOriginHTTPHeader,
		Attempt:   attempt,
	}}, nil
})
