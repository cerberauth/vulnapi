package report

import (
	"context"
	"net/http"
	"time"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/operation"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/x/telemetryx"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
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

	telemetryScanAttemptsCounter      metric.Int64Counter
	telemetryErrorsCounter            metric.Int64Counter
	telemetryIssuesCounter            metric.Int64Counter
	telemetryAverageDurationHistogram metric.Int64Histogram
}

const (
	otelName = "github.com/cerberauth/vulnapi/report"

	otelScanReportIdAttribute = attribute.Key("id")
)

func NewScanReport(id string, name string, operation *operation.Operation) *ScanReport {
	var scanOperation *ScanReportOperation
	if operation != nil && operation.ID != "" {
		scanOperation = &ScanReportOperation{
			ID: operation.ID,
		}
	}

	telemetryMeter := telemetryx.GetMeterProvider().Meter(otelName)
	telemetryScanAttemptsCounter, _ := telemetryMeter.Int64Counter("report.scan_attempts.counter")
	telemetryErrorsCounter, _ := telemetryMeter.Int64Counter("report.errors.counter")
	telemetryIssuesCounter, _ := telemetryMeter.Int64Counter("report.issues.counter")
	telemetryAverageDurationHistogram, _ := telemetryMeter.Int64Histogram("report.average_duration.histogram")

	return &ScanReport{
		ID:        id,
		Name:      name,
		StartTime: time.Now(),

		Operation: scanOperation,

		Scans:  []ScanReportScan{},
		Issues: []*IssueReport{},

		telemetryScanAttemptsCounter:      telemetryScanAttemptsCounter,
		telemetryErrorsCounter:            telemetryErrorsCounter,
		telemetryIssuesCounter:            telemetryIssuesCounter,
		telemetryAverageDurationHistogram: telemetryAverageDurationHistogram,
	}
}

func (r *ScanReport) Start() *ScanReport {
	r.StartTime = time.Now()
	return r
}

func (r *ScanReport) End() *ScanReport {
	r.EndTime = time.Now()
	r.telemetryAverageDurationHistogram.Record(context.Background(), int64(r.EndTime.Sub(r.StartTime).Milliseconds()), metric.WithAttributes(otelScanReportIdAttribute.String(r.ID)))
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

	attributes := metric.WithAttributes(
		otelScanReportIdAttribute.String(r.ID),
	)
	r.telemetryScanAttemptsCounter.Add(context.Background(), 1, attributes)
	if attempt.Err != nil {
		r.telemetryErrorsCounter.Add(context.Background(), 1, attributes)
	}

	return r
}

func (r *ScanReport) GetScanAttempts() []ScanReportScan {
	return r.Scans
}

func (r *ScanReport) AddIssueReport(vr *IssueReport) *ScanReport {
	r.Issues = append(r.Issues, vr)
	r.telemetryIssuesCounter.Add(context.Background(), 1, metric.WithAttributes(
		otelScanReportIdAttribute.String(r.ID),
		otelIssueIdAttribute.String(vr.ID),
	))
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
