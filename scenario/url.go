package scenario

import (
	"bytes"
	"errors"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/scan"
)

func NewURLScan(method string, u *url.URL, data string, client *request.Client, opts *scan.ScanOptions) (*scan.Scan, error) {
	if u == nil {
		return nil, errors.New("url is required")
	}

	if client == nil {
		client = request.GetDefaultClient()
	}

	securityScheme, err := detectSecurityScheme(client.Header)
	if err != nil {
		return nil, err
	}

	var securitySchemes []*auth.SecurityScheme
	if securityScheme != nil {
		securitySchemes = []*auth.SecurityScheme{securityScheme}
	} else {
		securitySchemes = []*auth.SecurityScheme{auth.MustNewNoAuthSecurityScheme()}
	}
	client.ClearSecuritySchemes(securitySchemes)

	body := bytes.NewBuffer([]byte(data))
	u = addDefaultProtocolWhenMissing(u)
	op, err := operation.NewOperation(method, u.String(), body, client)
	op.GenerateID()
	if err != nil {
		return nil, err
	}
	op.SetSecuritySchemes(securitySchemes)

	if err := op.IsReachable(); err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &scan.ScanOptions{}
	}

	if opts.Reporter == nil {
		var reportData interface{} = nil
		if data != "" {
			reportData = data
		}
		opts.Reporter = report.NewReporterWithCurl(method, u.String(), reportData, client.Header, client.Cookies, securitySchemes)
	}

	operations := operation.Operations{op}
	urlScan, err := scan.NewScan(operations, opts)
	if err != nil {
		return nil, err
	}

	WithAllCommonScans(urlScan)
	return urlScan, nil
}
