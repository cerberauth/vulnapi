package httptrack

import (
	"net/http"

	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTrackScanID   = "misconfiguration.http_track"
	HTTPTrackScanName = "HTTP TRACK Method Misconfiguration"
)

var issue = report.Issue{
	ID:   "security_misconfiguration.http_track_method_enabled",
	Name: "HTTP TRACK Method enabled",
	URL:  "https://techcommunity.microsoft.com/t5/iis-support-blog/http-track-and-trace-verbs/ba-p/784482",

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

const TrackMethod = "TRACK"

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(HTTPTrackScanID, HTTPTrackScanName, operation)

	newOperation := operation.Clone()
	newOperation.Method = TrackMethod

	attempt, err := scan.ScanURL(newOperation, &securityScheme)
	r.AddScanAttempt(attempt).End().AddVulnerabilityReport(vulnReport.WithBooleanStatus(err != nil || attempt.Response.StatusCode != http.StatusOK))

	return r, nil
}
