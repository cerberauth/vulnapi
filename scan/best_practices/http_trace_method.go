package bestpractices

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTraceMethodSeverityLevel            = 1
	HTTPTraceMethodVulnerabilityName        = "HTTP Trace Method enabled"
	HTTPTraceMethodVulnerabilityDescription = "HTTP Trace method seems enabled for this request."
)

func HTTPTraceMethodScanHandler(o *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	newOperation := o.Clone()
	newOperation.Method = "TRACE"

	token := ss.GetValidValue().(string)
	ss.SetAttackValue(token)
	vsa, err := request.ScanURL(&newOperation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Response.StatusCode < 300 {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: HTTPTraceMethodSeverityLevel,
			Name:          HTTPTraceMethodVulnerabilityName,
			Description:   HTTPTraceMethodVulnerabilityDescription,
			Url:           o.Url,
		})
	}

	return r, nil
}
