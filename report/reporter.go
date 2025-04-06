package report

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/getkin/kin-openapi/openapi3"
)

const reporterSchema = "https://schemas.cerberauth.com/vulnapi/draft/2024-10/report.schema.json"

type Reporter struct {
	Schema string `json:"$schema" yaml:"$schema"`

	Options     OptionsReport  `json:"options" yaml:"options"`
	Curl        *CurlReport    `json:"curl,omitempty" yaml:"curl,omitempty"`
	OpenAPI     *OpenAPIReport `json:"openapi,omitempty" yaml:"openapi,omitempty"`
	GraphQL     *GraphQLReport `json:"graphql,omitempty" yaml:"graphql,omitempty"`
	ScanReports []*ScanReport  `json:"reports" yaml:"reports"`
}

func NewReporter() *Reporter {
	return &Reporter{
		Schema: reporterSchema,

		Options:     NewOptionsReport(),
		ScanReports: []*ScanReport{},
	}
}

func NewReporterWithCurl(method string, url string, data interface{}, header http.Header, cookies []*http.Cookie, securitySchemes []*auth.SecurityScheme) *Reporter {
	return &Reporter{
		Schema: reporterSchema,

		Options:     NewOptionsReport(),
		Curl:        NewCurlReport(method, url, data, header, cookies, securitySchemes),
		ScanReports: []*ScanReport{},
	}
}

func NewReporterWithOpenAPIDoc(openapi *openapi3.T, operations operation.Operations) *Reporter {
	return &Reporter{
		Schema: reporterSchema,

		Options:     NewOptionsReport(),
		OpenAPI:     NewOpenAPIReport(openapi, operations),
		ScanReports: []*ScanReport{},
	}
}

func NewReporterWithGraphQL(url string, securitySchemes []*auth.SecurityScheme) *Reporter {
	return &Reporter{
		Schema: reporterSchema,

		Options:     NewOptionsReport(),
		GraphQL:     NewGraphQLReport(url, securitySchemes),
		ScanReports: []*ScanReport{},
	}
}

func (rr *Reporter) AddReport(r *ScanReport) {
	rr.ScanReports = append(rr.ScanReports, r)

	if rr.Curl != nil {
		rr.Curl.AddReport(r)
	}

	if rr.OpenAPI != nil {
		rr.OpenAPI.AddReport(r)
	}
}

func (rr *Reporter) GetScanReports() []*ScanReport {
	return rr.ScanReports
}

func (rr *Reporter) GetScanReportByID(id string) *ScanReport {
	for _, r := range rr.GetScanReports() {
		if r.ID == id {
			return r
		}
	}

	return nil
}

func (rr *Reporter) GetReportsByIssueStatus(status IssueReportStatus) []*ScanReport {
	var reports []*ScanReport
	for _, r := range rr.GetScanReports() {
		for _, ir := range r.GetIssueReports() {
			if ir.Status == status {
				reports = append(reports, r)
				break
			}
		}
	}

	return reports
}

func (rr *Reporter) GetErrors() []error {
	var errors []error
	for _, r := range rr.GetScanReports() {
		errors = append(errors, r.GetErrors()...)
	}

	return errors
}

func (rr *Reporter) HasIssue() bool {
	for _, r := range rr.GetScanReports() {
		if r.HasFailedIssueReport() {
			return true
		}
	}

	return false
}

func (rr *Reporter) GetIssueReports() []*IssueReport {
	var reports []*IssueReport
	for _, r := range rr.GetScanReports() {
		reports = append(reports, r.GetIssueReports()...)
	}
	return reports
}

func (rr *Reporter) GetFailedIssueReports() []*IssueReport {
	var reports []*IssueReport
	for _, r := range rr.GetScanReports() {
		reports = append(reports, r.GetFailedIssueReports()...)
	}
	return reports
}

func (rr *Reporter) HasHighRiskOrHigherSeverityIssue() bool {
	for _, r := range rr.GetFailedIssueReports() {
		if r.IsHighRiskSeverity() || r.IsCriticalRiskSeverity() {
			return true
		}
	}

	return false
}

func (rr *Reporter) HasHigherThanSeverityThresholdIssue(threshold float64) bool {
	for _, r := range rr.GetFailedIssueReports() {
		if r.CVSS.Score >= threshold {
			return true
		}
	}

	return false
}
