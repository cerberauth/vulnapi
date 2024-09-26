package httptrace

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTraceScanID   = "misconfiguration.http_trace"
	HTTPTraceScanName = "HTTP TRACE Method Misconfiguration"
)

var issue = report.Issue{
	ID:   "security_misconfiguration.http_trace_method_enabled",
	Name: "HTTP TRACE Method enabled",
	URL:  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/TRACE",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
		CWE:   report.CWE_489_Active_Debug_Code,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.Report, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(HTTPTraceScanID, HTTPTraceScanName, operation)

	newOperation := operation.Clone()
	newOperation.Method = http.MethodTrace

	attempt, err := scan.ScanURL(newOperation, &securityScheme)
	r.AddScanAttempt(attempt).End().AddVulnerabilityReport(vulnReport.WithBooleanStatus(err != nil || attempt.Response.StatusCode != http.StatusOK))

	return r, nil
}
