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

func ExtractBaseURL(inputURL *url.URL) *url.URL {
	baseURL := &url.URL{
		Scheme: inputURL.Scheme,
		Host:   inputURL.Host,
	}

	return baseURL
}

func CreateURLScanHandler(name string, seclistUrl string, defaultUrls []string, r *report.ScanReport, vulnReport *report.VulnerabilityReport) func(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	scanUrls := defaultUrls
	if urlsFromSeclist, err := seclist.NewSecListFromURL(name, seclistUrl); err == nil {
		scanUrls = urlsFromSeclist.Items
	}

	return func(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
		securityScheme.SetAttackValue(securityScheme.GetValidValue())
		securitySchemes := []auth.SecurityScheme{securityScheme}

		base := ExtractBaseURL(operation.Request.URL)
		for _, path := range scanUrls {
			newOperation, err := request.NewOperation(operation.Client, http.MethodGet, base.ResolveReference(&url.URL{Path: path}).String(), nil, nil, securitySchemes)
			if err != nil {
				return r, err
			}

			attempt, err := scan.ScanURL(newOperation, &securityScheme)
			r.AddScanAttempt(attempt).End()
			if err != nil {
				return r, err
			}

			if attempt.Response.StatusCode < 300 {
				r.AddVulnerabilityReport(vulnReport.WithOperation(newOperation))

				return r, nil
			}
		}

		return r, nil
	}
}
