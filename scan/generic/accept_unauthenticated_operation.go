package generic

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/internal/scan"
	"github.com/cerberauth/vulnapi/report"
)

const (
	NoAuthOperationScanID   = "generic.no_auth_operation"
	NoAuthOperationScanName = "No Auth Operation"

	NoAuthOperationVulnerabilitySeverityLevel     = 0
	NoAuthOperationVulnerabilityOWASP2023Category = report.OWASP2023BrokenAuthCategory
	NoAuthOperationVulnerabilityID                = "broken_authentication.no_auth_operation"
	NoAuthOperationVulnerabilityName              = "Operation May Accepts Unauthenticated Requests"
	NoAuthOperationVulnerabilityURL               = ""

	AcceptsUnauthenticatedOperationScanID   = "generic.accept_unauthenticated_operation"
	AcceptsUnauthenticatedOperationScanName = "Accept Unauthenticated Operation"

	AcceptUnauthenticatedOperationVulnerabilitySeverityLevel     = 9
	AcceptUnauthenticatedOperationVulnerabilityOWASP2023Category = report.OWASP2023BrokenAuthCategory
	AcceptUnauthenticatedOperationVulnerabilityID                = "broken_authentication.accept_unauthenticated_operation"
	AcceptUnauthenticatedOperationVulnerabilityName              = "Operation Accepts Unauthenticated Requests"
	AcceptUnauthenticatedOperationVulnerabilityURL               = ""
)

func NoAuthOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(NoAuthOperationScanID, NoAuthOperationScanName)
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: NoAuthOperationVulnerabilitySeverityLevel,

			OWASP2023Category: NoAuthOperationVulnerabilityOWASP2023Category,

			ID:   NoAuthOperationVulnerabilityID,
			Name: NoAuthOperationVulnerabilityName,
			URL:  NoAuthOperationVulnerabilityURL,

			Operation: operation,
		})
	}

	r.End()
	return r, nil
}

func AcceptUnauthenticatedOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport(AcceptsUnauthenticatedOperationScanID, AcceptsUnauthenticatedOperationScanName)
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		return r, nil
	}

	noAuthSecurityScheme := auth.SecurityScheme(auth.NewNoAuthSecurityScheme())
	vsa, err := scan.ScanURL(operation, &noAuthSecurityScheme)
	if err != nil {
		return r, err
	}
	r.AddScanAttempt(vsa).End()

	if err := scan.DetectNotExpectedResponse(vsa.Response); err != nil {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: AcceptUnauthenticatedOperationVulnerabilitySeverityLevel,

			OWASP2023Category: AcceptUnauthenticatedOperationVulnerabilityOWASP2023Category,

			ID:   AcceptUnauthenticatedOperationVulnerabilityID,
			Name: AcceptUnauthenticatedOperationVulnerabilityName,
			URL:  AcceptUnauthenticatedOperationVulnerabilityURL,

			Operation: operation,
		})
	}

	return r, nil
}
