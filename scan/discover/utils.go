package discover

import (
	"net/http"
	"net/url"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
	"github.com/cerberauth/vulnapi/seclist"
)

type DiscoverData struct {
	URL string
}

func ExtractBaseURL(inputURL *url.URL) *url.URL {
	baseURL := &url.URL{
		Scheme: inputURL.Scheme,
		Host:   inputURL.Host,
	}

	return baseURL
}

func ScanURLs(scanUrls []string, operation *request.Operation, securityScheme auth.SecurityScheme, r *report.ScanReport, vulnReport *report.VulnerabilityReport) (*report.ScanReport, error) {
	securitySchemes := []auth.SecurityScheme{securityScheme}

	base := ExtractBaseURL(operation.Request.URL)
	for _, path := range scanUrls {
		newOperation, err := request.NewOperation(operation.Client, http.MethodGet, base.ResolveReference(&url.URL{Path: path}).String(), nil, nil, securitySchemes)
		if err != nil {
			return r, err
		}

		attempt, err := scan.ScanURL(newOperation, &securityScheme)
		if err != nil {
			return r, err
		}

		r.AddScanAttempt(attempt)
		if attempt.Response.StatusCode == http.StatusOK { // TODO: check if the response contains the expected content
			r.WithData(DiscoverData{
				URL: attempt.Request.URL.String(),
			}).AddVulnerabilityReport(vulnReport.Fail()).End()
			return r, nil
		}
	}

	r.AddVulnerabilityReport(vulnReport.Pass()).End()
	return r, nil
}

func CreateURLScanHandler(name string, seclistUrl string, defaultUrls []string, r *report.ScanReport, vulnReport *report.VulnerabilityReport) func(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	scanUrls := defaultUrls
	if urlsFromSeclist, err := seclist.NewSecListFromURL(name, seclistUrl); err == nil && urlsFromSeclist != nil {
		scanUrls = urlsFromSeclist.Items
	}

	return func(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
		return ScanURLs(scanUrls, operation, securityScheme, r, vulnReport)
	}
}
