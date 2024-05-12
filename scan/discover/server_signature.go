package discover

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverServerSignatureScanID   = "discover.server_signature"
	DiscoverServerSignatureScanName = "Server Signature Discovery"

	ServerSignatureSeverityLevel     = 0
	ServerSignatureOWASP2023Category = report.OWASP2023SecurityMisconfigurationCategory
	ServerSignatureVulnerabilityID   = "security_misconfiguration.server_signature"
	ServerSignatureVulnerabilityName = "Server Signature Exposed"
	ServerSignatureVulnerabilityURL  = ""
)

var signatureHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

func checkSignatureHeader(operation *request.Operation, headers map[string][]string, r *report.ScanReport) bool {
	for _, header := range signatureHeaders {
		value := headers[header]
		if len(value) > 0 {
			r.AddVulnerabilityReport(&report.VulnerabilityReport{
				SeverityLevel: ServerSignatureSeverityLevel,

				OWASP2023Category: ServerSignatureOWASP2023Category,

				ID:   ServerSignatureVulnerabilityID,
				Name: ServerSignatureVulnerabilityName,
				URL:  ServerSignatureVulnerabilityURL,

				Operation: operation,
			})

			return false
		}
	}

	return true
}

func ServerSignatureScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vsa, err := scan.ScanURL(operation, &securityScheme)
	r := report.NewScanReport(DiscoverServerSignatureScanID, DiscoverServerSignatureScanName)
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
