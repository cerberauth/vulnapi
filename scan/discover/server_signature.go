package discover

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverServerSignatureScanID   = "discover.server-signature"
	DiscoverServerSignatureScanName = "Server Signature Discovery"

	ServerSignatureSeverityLevel            = 0
	ServerSignatureVulnerabilityName        = "Server Signature Exposed"
	ServerSignatureVulnerabilityDescription = "A Server signature is exposed in an header."
)

var signatureHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

func checkSignatureHeader(operation *request.Operation, headers map[string][]string, r *report.ScanReport) bool {
	for _, header := range signatureHeaders {
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

func ServerSignatureScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(DiscoverServerSignatureScanID, DiscoverServerSignatureScanName)

	securityScheme.SetAttackValue(securityScheme.GetValidValue())
	vsa, err := scan.ScanURL(operation, &securityScheme)
	r.AddScanAttempt(vsa).End()
	if err != nil {
		return r, err
	}

	if vsa.Err != nil {
		return r, vsa.Err
	}

	checkSignatureHeader(operation, vsa.Response.Header, r)

	return r, nil
}
