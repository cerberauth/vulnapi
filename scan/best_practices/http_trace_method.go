package bestpractices

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTraceMethodSeverityLevel            = 1
	HTTPTraceMethodVulnerabilityName        = "HTTP Trace Method enabled"
	HTTPTraceMethodVulnerabilityDescription = "HTTP Trace method seems enabled for this request."
)

func HTTPTraceMethodScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	newOperation := operation.Clone()
	newOperation.Method = "TRACE"

	ss.SetAttackValue(ss.GetValidValue())
	vsa, err := scan.ScanURL(newOperation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HTTPTraceMethodSeverityLevel,
			Name:          HTTPTraceMethodVulnerabilityName,
			Description:   HTTPTraceMethodVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
