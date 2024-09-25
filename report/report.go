package report

import (
	"net/http"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
)

type ReportRequest struct {
	Method  string         `json:"method" yaml:"method"`
	URL     string         `json:"url" yaml:"url"`
	Body    *string        `json:"body,omitempty" yaml:"body,omitempty"`
	Cookies []*http.Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header  http.Header    `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type ReportResponse struct {
	StatusCode int            `json:"statusCode" yaml:"statusCode"`
	Body       string         `json:"body" yaml:"body"`
	Cookies    []*http.Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header     http.Header    `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type ReportScan struct {
	Request  *ReportRequest  `json:"request,omitempty" yaml:"request,omitempty"`
	Response *ReportResponse `json:"response,omitempty" yaml:"response,omitempty"`
	Err      error           `json:"error,omitempty" yaml:"error,omitempty"`
}

type ReportOperationSecurityScheme struct {
	Type   auth.Type       `json:"type" yaml:"type"`
	Scheme auth.SchemeName `json:"scheme" yaml:"scheme"`
	In     *auth.SchemeIn  `json:"in,omitempty" yaml:"in,omitempty"`
	Name   string          `json:"name" yaml:"name"`
}

type ReportOperation struct {
	ID   string   `json:"id" yaml:"id"`
	Tags []string `json:"tags" yaml:"tags"`

	Method  string         `json:"method" yaml:"method"`
	URL     string         `json:"url" yaml:"url"`
	Cookies []*http.Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header  http.Header    `json:"headers,omitempty" yaml:"headers,omitempty"`

	SecuritySchemes []ReportOperationSecurityScheme `json:"securitySchemes" yaml:"securitySchemes"`
}

type Report struct {
	ID        string    `json:"id" yaml:"id"`
	Name      string    `json:"name" yaml:"name"`
	StartTime time.Time `json:"startTime" yaml:"startTime"`
	EndTime   time.Time `json:"endTime,omitempty" yaml:"endTime,omitempty"`

	Operation ReportOperation `json:"operation" yaml:"operation"`

	Data  interface{}            `json:"data,omitempty" yaml:"data,omitempty"`
	Scans []ReportScan           `json:"scans" yaml:"scans"`
	Vulns []*VulnerabilityReport `json:"vulnerabilities" yaml:"vulnerabilities"`
}

func NewScanReport(id string, name string, operation *request.Operation) *Report {
	securitySchemes := []ReportOperationSecurityScheme{}
	for _, ss := range operation.SecuritySchemes {
		securitySchemes = append(securitySchemes, ReportOperationSecurityScheme{
			Type:   ss.GetType(),
			Scheme: ss.GetScheme(),
			In:     ss.GetIn(),
			Name:   ss.GetName(),
		})
	}

	return &Report{
		ID:        id,
		Name:      name,
		StartTime: time.Now(),

		Operation: ReportOperation{
			ID:   operation.ID,
			Tags: operation.Tags,

			Method:  operation.Method,
			URL:     operation.URL.String(),
			Cookies: operation.Cookies,
			Header:  operation.Header,

			SecuritySchemes: securitySchemes,
		},

		Scans: []ReportScan{},
		Vulns: []*VulnerabilityReport{},
	}
}

func (r *Report) Start() *Report {
	r.StartTime = time.Now()
	return r
}

func (r *Report) End() *Report {
	r.EndTime = time.Now()
	return r
}

func (r *Report) WithData(data interface{}) *Report {
	r.Data = data
	return r
}

func (r *Report) GetData() interface{} {
	return r.Data
}

func (r *Report) HasData() bool {
	return r.Data != nil
}

func (r *Report) AddScanAttempt(a *scan.VulnerabilityScanAttempt) *Report {
	var reportRequest *ReportRequest = nil
	if a.Request != nil {
		reportRequest = &ReportRequest{
			Method:  a.Request.Method,
			URL:     a.Request.URL.String(),
			Cookies: a.Request.Cookies(),
			Header:  a.Request.Header,
		}
	}

	var reportResponse *ReportResponse = nil
	if a.Response != nil {
		reportResponse = &ReportResponse{
			StatusCode: a.Response.StatusCode,
			Cookies:    a.Response.Cookies(),
			Header:     a.Response.Header,
		}
	}

	r.Scans = append(r.Scans, ReportScan{
		Request:  reportRequest,
		Response: reportResponse,
		Err:      a.Err,
	})
	return r
}

func (r *Report) GetScanAttempts() []ReportScan {
	return r.Scans
}

func (r *Report) AddVulnerabilityReport(vr *VulnerabilityReport) *Report {
	r.Vulns = append(r.Vulns, vr)
	return r
}

func (r *Report) GetVulnerabilityReports() []*VulnerabilityReport {
	return r.Vulns
}

func (r *Report) GetErrors() []error {
	var errors []error
	for _, sa := range r.GetScanAttempts() {
		if sa.Err != nil {
			errors = append(errors, sa.Err)
		}
	}
	return errors
}

func (r *Report) GetFailedVulnerabilityReports() []*VulnerabilityReport {
	var failedReports []*VulnerabilityReport
	for _, vr := range r.GetVulnerabilityReports() {
		if vr.HasFailed() {
			failedReports = append(failedReports, vr)
		}
	}
	return failedReports
}

func (r *Report) HasFailedVulnerabilityReport() bool {
	return len(r.GetFailedVulnerabilityReports()) > 0
}
