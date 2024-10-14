package report

import (
	"net/http"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
)

type OperationSecurityScheme struct {
	Type   auth.Type       `json:"type" yaml:"type"`
	Scheme auth.SchemeName `json:"scheme" yaml:"scheme"`
	In     *auth.SchemeIn  `json:"in,omitempty" yaml:"in,omitempty"`
	Name   string          `json:"name" yaml:"name"`
}

func NewOperationSecurityScheme(ss auth.SecurityScheme) OperationSecurityScheme {
	return OperationSecurityScheme{
		Type:   ss.GetType(),
		Scheme: ss.GetScheme(),
		In:     ss.GetIn(),
		Name:   ss.GetName(),
	}
}

type ScanReportRequest struct {
	Method  string         `json:"method" yaml:"method"`
	URL     string         `json:"url" yaml:"url"`
	Body    *string        `json:"body,omitempty" yaml:"body,omitempty"`
	Cookies []*http.Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header  http.Header    `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type ScanReportResponse struct {
	StatusCode int            `json:"statusCode" yaml:"statusCode"`
	Body       *string        `json:"body,omitempty" yaml:"body,omitempty"`
	Cookies    []*http.Cookie `json:"cookies,omitempty" yaml:"cookies,omitempty"`
	Header     http.Header    `json:"headers,omitempty" yaml:"headers,omitempty"`
}

type ScanReportScan struct {
	Request  *ScanReportRequest  `json:"request,omitempty" yaml:"request,omitempty"`
	Response *ScanReportResponse `json:"response,omitempty" yaml:"response,omitempty"`
	Err      error               `json:"error,omitempty" yaml:"error,omitempty"`
}

type ScanReportOperation struct {
	ID string `json:"id" yaml:"id"`
}
type ScanReport struct {
	ID        string    `json:"id" yaml:"id"`
	Name      string    `json:"name" yaml:"name"`
	StartTime time.Time `json:"startTime" yaml:"startTime"`
	EndTime   time.Time `json:"endTime,omitempty" yaml:"endTime,omitempty"`

	Operation *ScanReportOperation `json:"operation,omitempty" yaml:"operation,omitempty"`

	Data   interface{}      `json:"data,omitempty" yaml:"data,omitempty"`
	Scans  []ScanReportScan `json:"scans" yaml:"scans"`
	Issues []*IssueReport   `json:"issues" yaml:"issues"`
}

func NewScanReport(id string, name string, operation *request.Operation) *ScanReport {
	var scanOperation *ScanReportOperation
	if operation != nil && operation.ID != "" {
		scanOperation = &ScanReportOperation{
			ID: operation.ID,
		}
	}

	return &ScanReport{
		ID:        id,
		Name:      name,
		StartTime: time.Now(),

		Operation: scanOperation,

		Scans:  []ScanReportScan{},
		Issues: []*IssueReport{},
	}
}

func (r *ScanReport) Start() *ScanReport {
	r.StartTime = time.Now()
	return r
}

func (r *ScanReport) End() *ScanReport {
	r.EndTime = time.Now()
	return r
}

func (r *ScanReport) WithData(data interface{}) *ScanReport {
	r.Data = data
	return r
}

func (r *ScanReport) GetData() interface{} {
	return r.Data
}

func (r *ScanReport) HasData() bool {
	return r.Data != nil
}

func (r *ScanReport) AddScanAttempt(a *scan.IssueScanAttempt) *ScanReport {
	var reportRequest *ScanReportRequest = nil
	if a.Request != nil {
		reportRequest = &ScanReportRequest{
			Method:  a.Request.Method,
			URL:     a.Request.URL.String(),
			Cookies: a.Request.Cookies(),
			Header:  a.Request.Header,
		}
	}

	var reportResponse *ScanReportResponse = nil
	if a.Response != nil {
		reportResponse = &ScanReportResponse{
			StatusCode: a.Response.StatusCode,
			Cookies:    a.Response.Cookies(),
			Header:     a.Response.Header,
		}
	}

	r.Scans = append(r.Scans, ScanReportScan{
		Request:  reportRequest,
		Response: reportResponse,
		Err:      a.Err,
	})
	return r
}

func (r *ScanReport) GetScanAttempts() []ScanReportScan {
	return r.Scans
}

func (r *ScanReport) AddIssueReport(vr *IssueReport) *ScanReport {
	r.Issues = append(r.Issues, vr)
	return r
}

func (r *ScanReport) GetIssueReports() []*IssueReport {
	return r.Issues
}

func (r *ScanReport) GetErrors() []error {
	var errors []error
	for _, sa := range r.GetScanAttempts() {
		if sa.Err != nil {
			errors = append(errors, sa.Err)
		}
	}
	return errors
}

func (r *ScanReport) GetFailedIssueReports() []*IssueReport {
	var failedReports []*IssueReport
	for _, vr := range r.GetIssueReports() {
		if vr.HasFailed() {
			failedReports = append(failedReports, vr)
		}
	}
	return failedReports
}

func (r *ScanReport) HasFailedIssueReport() bool {
	return len(r.GetFailedIssueReports()) > 0
}
