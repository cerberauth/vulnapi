package discover

import (
	"net/http"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/seclist"
)

type DiscoverData struct {
	URL string
}

func ExtractBaseURL(inputURL *url.URL) *url.URL {
	return &url.URL{
		Scheme: inputURL.Scheme,
		Host:   inputURL.Host,
	}
}

func ScanURLs(scanUrls []string, op *operation.Operation, securityScheme auth.SecurityScheme, r *report.ScanReport, vulnReport *report.IssueReport) (*report.ScanReport, error) {
	securitySchemes := []auth.SecurityScheme{securityScheme}

	base := ExtractBaseURL(&op.URL)
	for _, path := range scanUrls {
		newOperation, err := operation.NewOperation(http.MethodGet, base.ResolveReference(&url.URL{Path: path}).String(), nil, op.Client)
		newOperation.SetSecuritySchemes(securitySchemes)
		if err != nil {
			return r, err
		}

		attempt, err := scan.ScanURL(newOperation, &securityScheme)
		if err != nil {
			return r, err
		}

		r.AddScanAttempt(attempt)
		if attempt.Response.GetStatusCode() == http.StatusOK { // TODO: check if the response contains the expected content
			r.WithData(DiscoverData{
				URL: attempt.Request.GetURL(),
			}).AddIssueReport(vulnReport.Fail()).End()
			return r, nil
		}
	}

	r.AddIssueReport(vulnReport.Pass()).End()
	return r, nil
}

func CreateURLScanHandler(name string, seclistUrl string, defaultUrls []string, r *report.ScanReport, vulnReport *report.IssueReport) func(operation *operation.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	scanUrls := defaultUrls
	if urlsFromSeclist, err := seclist.NewSecListFromURL(name, seclistUrl); err == nil && urlsFromSeclist != nil {
		scanUrls = urlsFromSeclist.Items
	}

	return func(op *operation.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
		return ScanURLs(scanUrls, op, securityScheme, r, vulnReport)
	}
}
