package bestpractices

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	restapi "github.com/cerberauth/vulnapi/internal/rest_api"
	"github.com/cerberauth/vulnapi/report"
)

const (
	HTTPTraceMethodSeverityLevel            = 1
	HTTPTraceMethodVulnerabilityName        = "HTTP Trace Method enabled"
	HTTPTraceMethodVulnerabilityDescription = "HTTP Trace method seems enabled for this request."
)

func HTTPTraceMethodScanHandler(o *auth.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	newOperation := o.Clone()
	newOperation.Method = "TRACE"

	token := ss.GetValidValue().(string)
	ss.SetAttackValue(token)
	vsa := restapi.ScanRestAPI(&newOperation, ss)
	r.AddScanAttempt(vsa).End()

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
