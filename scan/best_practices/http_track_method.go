package bestpractices

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTrackScanID   = "best_practices.http_track"
	HTTPTrackScanName = "HTTP TRACK Method Best Practices"

	HTTPTrackMethodSeverityLevel     = 0
	HTTPTrackMethodOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	HTTPTrackMethodVulnerabilityID   = "security_misconfiguration.http_track_method"
	HTTPTrackMethodVulnerabilityName = "HTTP TRACK Method enabled"
	HTTPTrackMethodVulnerabilityURL  = "https://techcommunity.microsoft.com/t5/iis-support-blog/http-track-and-trace-verbs/ba-p/784482"
)

func HTTPTrackMethodScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	newOperation := operation.Clone()
	newOperation.Method = "TRACK"

	vsa, err := scan.ScanURL(newOperation, &ss)
	r := report.NewScanReport(HTTPTrackScanID, HTTPTrackScanName, operation)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HTTPTrackMethodSeverityLevel,

			OWASP2023Category: HTTPTrackMethodOWASP2023Category,

			ID:   HTTPTrackMethodVulnerabilityID,
			Name: HTTPTrackMethodVulnerabilityName,
			URL:  HTTPTrackMethodVulnerabilityURL,
		})
	}

	return r, nil
}
