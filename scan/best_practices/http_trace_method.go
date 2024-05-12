package bestpractices

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTraceScanID   = "best_practices.http_trace"
	HTTPTraceScanName = "HTTP TRACE Method Best Practices"

	HTTPTraceMethodSeverityLevel     = 0
	HTTPTraceMethodOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTTPTraceMethodVulnerabilityID   = "security_misconfiguration.http_trace_method"
	HTTPTraceMethodVulnerabilityName = "HTTP TRACE Method enabled"
	HTTPTraceMethodVulnerabilityURL  = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/TRACE"
)

func HTTPTraceMethodScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	newOperation := operation.Clone()
	newOperation.Method = http.MethodTrace

	vsa, err := scan.ScanURL(newOperation, &ss)
	r := report.NewScanReport(HTTPTraceScanID, HTTPTraceScanName)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HTTPTraceMethodSeverityLevel,

			OWASP2023Category: HTTPTraceMethodOWASP2023Category,

			ID:   HTTPTraceMethodVulnerabilityID,
			Name: HTTPTraceMethodVulnerabilityName,
			URL:  HTTPTraceMethodVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
