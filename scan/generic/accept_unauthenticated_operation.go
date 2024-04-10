package generic

import (
	"github.com/cerberauth/vulnapi/internal/auth"
	"github.com/cerberauth/vulnapi/internal/request"
	"github.com/cerberauth/vulnapi/report"
)

const (
	AcceptUnauthenticatedOperationVulnerabilityLevel       = 0
	AcceptUnauthenticatedOperationVulnerabilityName        = "Operation Accepts Unauthenticated Requests"
	AcceptUnauthenticatedOperationVulnerabilityDescription = "The operation accepts unauthenticated requests or the authenticated scheme has not been detected. This can lead to unauthorized access and security issues."
)

func AcceptUnauthenticatedOperationScanHandler(operation *request.Operation, securityScheme auth.SecurityScheme) (*report.ScanReport, error) {
	r := report.NewScanReport()
	if _, ok := securityScheme.(*auth.NoAuthSecurityScheme); ok {
		r.AddVulnerabilityReport(&report.VulnerabilityReport{
			SeverityLevel: AcceptUnauthenticatedOperationVulnerabilityLevel,
			Name:          AcceptUnauthenticatedOperationVulnerabilityName,
			Description:   AcceptUnauthenticatedOperationVulnerabilityDescription,
			Operation:     operation,
		})
	}

	return r, nil
}
