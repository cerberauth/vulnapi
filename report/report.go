package report

import (
	"net/http"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"go.opentelemetry.io/otel"
)

type OperationSecurityScheme struct {
	Type        auth.Type        `json:"type" yaml:"type"`
	Scheme      auth.SchemeName  `json:"scheme" yaml:"scheme"`
	In          *auth.SchemeIn   `json:"in" yaml:"in"`
	TokenFormat auth.TokenFormat `json:"tokenFormat" yaml:"tokenFormat"`

	Name string `json:"name" yaml:"name"`
}

func NewOperationSecurityScheme(securityScheme *auth.SecurityScheme) OperationSecurityScheme {
	tokenFormat := auth.NoneTokenFormat
	if securityScheme.GetTokenFormat() != nil {
		tokenFormat = *securityScheme.GetTokenFormat()
	}

	return OperationSecurityScheme{
		Type:        securityScheme.GetType(),
		Scheme:      securityScheme.GetScheme(),
		In:          securityScheme.GetIn(),
		TokenFormat: tokenFormat,

		Name: securityScheme.GetName(),
	}
}

type ScanReportRequest struct {
	ID      string         `json:"id" yaml:"id"`
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
	ID       string              `json:"id" yaml:"id"`
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

var tracer = otel.Tracer("report")

func NewScanReport(id string, name string, operation *operation.Operation) *ScanReport {
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

func (r *ScanReport) AddScanAttempt(attempt *scan.IssueScanAttempt) *ScanReport {
	var reportRequest *ScanReportRequest = nil
	if attempt.Request != nil {
		reportRequest = &ScanReportRequest{
			ID:      attempt.Request.GetID(),
			Method:  attempt.Request.GetMethod(),
			URL:     attempt.Request.GetURL(),
			Cookies: attempt.Request.GetCookies(),
			Header:  attempt.Request.GetHeader(),
		}
	}

	var reportResponse *ScanReportResponse = nil
	if attempt.Response != nil {
		var body string
		if attempt.Response.GetBody() != nil {
			body = attempt.Response.GetBody().String()
		}

		reportResponse = &ScanReportResponse{
			StatusCode: attempt.Response.GetStatusCode(),
			Body:       &body,
			Cookies:    attempt.Response.GetCookies(),
			Header:     attempt.Response.GetHeader(),
		}
	}

	r.Scans = append(r.Scans, ScanReportScan{
		ID:       attempt.ID,
		Request:  reportRequest,
		Response: reportResponse,
		Err:      attempt.Err,
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

// GetFilteredByThreshold returns a copy of the scan report with only issues that meet or exceed the severity threshold
func (r *ScanReport) GetFilteredByThreshold(threshold float64) *ScanReport {
	var filteredIssues []*IssueReport
	var hasFailedIssueAboveThreshold bool
	
	for _, issue := range r.GetIssueReports() {
		// Always include passed and skipped issues regardless of threshold
		if !issue.HasFailed() {
			filteredIssues = append(filteredIssues, issue)
		} else if issue.CVSS.Score >= threshold {
			// Only include failed issues that meet the threshold
			filteredIssues = append(filteredIssues, issue)
			hasFailedIssueAboveThreshold = true
		}
	}
	
	// Return nil if no failed issues meet the threshold (only if there are no passed/skipped issues either)
	if !hasFailedIssueAboveThreshold && len(filteredIssues) == 0 {
		return nil
	}
	
	// Create a copy of the scan report with filtered issues
	filteredReport := &ScanReport{
		ID:        r.ID,
		Name:      r.Name,
		StartTime: r.StartTime,
		EndTime:   r.EndTime,
		Operation: r.Operation,
		Data:      r.Data,
		Scans:     r.Scans, // Keep all scan attempts
		Issues:    filteredIssues,
	}
	
	return filteredReport
}
