package serversignature

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	DiscoverServerSignatureScanID   = "discover.server_signature"
	DiscoverServerSignatureScanName = "Server Signature Discovery"
)

var issue = report.Issue{
	ID:   "discover.server_signature",
	Name: " Server Signature Exposed",

	Classifications: &report.Classifications{
		OWASP: report.OWASP_2023_SecurityMisconfiguration,
	},

	CVSS: report.CVSS{
		Version: 4.0,
		Vector:  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
		Score:   0,
	},
}

var signatureHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

func checkSignatureHeader(headers map[string][]string) bool {
	for _, header := range signatureHeaders {
		value := headers[header]
		if len(value) > 0 {
			return false
		}
	}

	return true
}

func ScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	vulnReport := report.NewVulnerabilityReport(issue).WithOperation(operation).WithSecurityScheme(securityScheme)
	r := report.NewScanReport(DiscoverServerSignatureScanID, DiscoverServerSignatureScanName, operation)

	vsa, err := scan.ScanURL(operation, &securityScheme)
	r.AddScanAttempt(vsa)
	if err != nil {
		r.AddVulnerabilityReport(vulnReport.Skip()).End()
		return r, err
	}

	if vsa.Err != nil {
		r.AddVulnerabilityReport(vulnReport.Skip()).End()
		return r, vsa.Err
	}

	vulnReport.WithBooleanStatus(checkSignatureHeader(vsa.Response.Header))
	r.AddVulnerabilityReport(vulnReport).End()

	return r, nil
}
