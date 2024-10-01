package report

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
)

type CurlReport struct {
	Method  string         `json:"method" yaml:"method"`
	URL     string         `json:"url" yaml:"url"`
	Data    interface{}    `json:"data,omitempty" yaml:"data,omitempty"`
	Header  http.Header    `json:"headers,omitempty" yaml:"headers,omitempty"`
	Cookies []*http.Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`

	SecuritySchemes []OperationSecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`

	Issues []*IssueReport `json:"issues" yaml:"issues"`
}

func NewCurlReport(method string, url string, data interface{}, header http.Header, cookies []*http.Cookie, securitySchemes []auth.SecurityScheme) *CurlReport {
	reportSecuritySchemes := []OperationSecurityScheme{}
	for _, ss := range securitySchemes {
		reportSecuritySchemes = append(reportSecuritySchemes, NewOperationSecurityScheme(ss))
	}

	return &CurlReport{
		Method:  method,
		URL:     url,
		Data:    data,
		Header:  header,
		Cookies: cookies,

		SecuritySchemes: reportSecuritySchemes,

		Issues: []*IssueReport{},
	}
}

func (cr *CurlReport) AddReport(r *ScanReport) {
	if r.HasFailedIssueReport() {
		cr.Issues = append(cr.Issues, r.GetFailedIssueReports()...)
	}
}
