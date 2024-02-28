package bestpractices

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	ServerSignatureSeverityLevel            = 1
	ServerSignatureVulnerabilityName        = "Server Signature Exposed"
	ServerSignatureVulnerabilityDescription = "A Server signature is exposed in an header."
)

var SignatureHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

func CheckSignatureHeader(operation *request.Operation, headers map[string][]string, r *report.ScanReport) bool {
	for _, header := range SignatureHeaders {
		value := headers[header]
		if len(value) > 0 {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: ServerSignatureSeverityLevel,
				Name:          ServerSignatureVulnerabilityName,
				Description:   ServerSignatureVulnerabilityDescription,
				Operation:     operation,
			})

			return false
		}
	}

	return true
}

func ServerSignatureScanHandler(operation *request.Operation, ss auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()

	ss.SetAttackValue(ss.GetValidValue())
	vsa, err := scan.ScanURL(operation, &ss)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Err != nil {
		return r, vsa.Err
	}

	CheckSignatureHeader(operation, vsa.Response.Header, r)

	return r, nil
}
